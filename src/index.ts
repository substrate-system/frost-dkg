/**
 * FROST DKG Implementation using @noble/curves
 * Based on: https://eprint.iacr.org/2020/852.pdf
 *
 * Install dependencies:
 * npm install @noble/curves @noble/hashes
 *
 * For testing:
 * npm install --save-dev @noble/curves @noble/hashes
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToNumberLE } from '@noble/curves/utils.js'

// Ed25519 curve order
const CURVE_ORDER = ed25519.Point.CURVE().n

/**
 * Modular arithmetic helper
 */
function mod (n, m = CURVE_ORDER) {
    const result = n % m
    return result >= 0n ? result : result + m
}

function modAdd (a, b) {
    return mod(a + b)
}

function modMul (a, b) {
    return mod(a * b)
}

function modPow (base, exp, modulus = CURVE_ORDER) {
    if (modulus === 1n) return 0n
    let result = 1n
    base = mod(base, modulus)
    let e = exp
    while (e > 0n) {
        if (e & 1n) result = mod(result * base, modulus)
        e = e >> 1n
        base = mod(base * base, modulus)
    }
    return result
}

/**
 * Generate random scalar in range [1, CURVE_ORDER)
 */
export function randomScalar () {
    const bytes = randomBytes(32)
    const num = bytesToNumberLE(bytes)
    return mod(num) || 1n // Ensure non-zero
}

/**
 * Hash to scalar using SHA-512
 */
function hashToScalar (...inputs) {
    const concat = new Uint8Array(inputs.reduce((acc, inp) => acc + inp.length, 0))
    let offset = 0
    for (const input of inputs) {
        concat.set(input, offset)
        offset += input.length
    }

    const hash = sha512(concat)
    const num = bytesToNumberLE(hash)
    return mod(num)
}

/**
 * Convert bigint to 32-byte little-endian array
 */
export function scalarToBytes (scalar) {
    const bytes = new Uint8Array(32)
    let n = BigInt(scalar)
    for (let i = 0; i < 32; i++) {
        bytes[i] = Number(n & 0xFFn)
        n >>= 8n
    }
    return bytes
}

/**
 * Convert bigint to bytes for point serialization
 */
function bigintToBytes (n) {
    return scalarToBytes(n)
}

/**
 * X25519 key generation and ECDH
 */
async function generateX25519KeyPair () {
    return await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits']
    )
}

export async function deriveSharedSecret (privateKey, publicKey) {
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'X25519', public: publicKey },
        privateKey,
        256
    )
    return new Uint8Array(sharedSecret)
}

/**
 * Encrypt/Decrypt using AES-GCM with derived key
 */
export async function encryptShare (sharedSecret, plaintext) {
    const keyMaterial = await crypto.subtle.digest('SHA-256', sharedSecret)
    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintext
    )

    const result = new Uint8Array(iv.length + ciphertext.byteLength)
    result.set(iv)
    result.set(new Uint8Array(ciphertext), iv.length)
    return result
}

export async function decryptShare (sharedSecret, encrypted) {
    const iv = encrypted.slice(0, 12)
    const ciphertext = encrypted.slice(12)

    const keyMaterial = await crypto.subtle.digest('SHA-256', sharedSecret)
    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )

    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    )

    return new Uint8Array(plaintext)
}

/**
 * FROST DKG Participant
 */
export class FrostParticipant {
    public id:bigint
    public threshold:number
    public n:number
    public coefficients:bigint[] | null
    public commitments:any[] | null
    public proofOfKnowledge:any
    public x25519KeyPair:any
    public peerPublicKeys:Map<bigint, any>
    public shares:Map<bigint, bigint>
    public receivedShares:Map<bigint, any>
    public secretShare:bigint | null
    public verificationShare:any
    public publicKey:any

    constructor (id, threshold, totalParticipants) {
        this.id = BigInt(id)
        this.threshold = threshold
        this.n = totalParticipants

        // Polynomial coefficients (scalars)
        this.coefficients = null
        // Commitments (curve points)
        this.commitments = null
        // Proof of knowledge
        this.proofOfKnowledge = null

        // X25519 keys for encrypted communication
        this.x25519KeyPair = null
        this.peerPublicKeys = new Map()

        // Shares for other participants
        this.shares = new Map()
        // Received shares from other participants
        this.receivedShares = new Map()

        // Final results
        this.secretShare = null
        this.verificationShare = null
        this.publicKey = null
    }

    /**
   * Initialize with X25519 keypair for encrypted channels
   */
    async initialize () {
        this.x25519KeyPair = await generateX25519KeyPair()
        return await crypto.subtle.exportKey('raw', this.x25519KeyPair.publicKey)
    }

    /**
   * Register peer's X25519 public key
   */
    async registerPeerKey (peerId, publicKeyBytes) {
        const publicKey = await crypto.subtle.importKey(
            'raw',
            publicKeyBytes,
            { name: 'X25519' },
            true,
            []
        )
        this.peerPublicKeys.set(BigInt(peerId), publicKey)
    }

    /**
   * Round 1: Generate polynomial and commitments
   * f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,t-1}*x^{t-1}
   * C_{i,k} = g^{a_{i,k}}
   */
    async round1_generateCommitments () {
    // Generate random polynomial coefficients
        this.coefficients = []
        for (let i = 0; i < this.threshold; i++) {
            this.coefficients.push(randomScalar())
        }

        // Generate commitments: C_k = g^{a_k}
        this.commitments = []
        for (const coeff of this.coefficients) {
            const point = ed25519.Point.BASE.multiply(coeff)
            this.commitments.push(point)
        }

        // Generate Schnorr proof of knowledge for secret (a_0)
        this.proofOfKnowledge = this.generateSchnorrProof(this.coefficients[0])

        return {
            participantId: this.id,
            commitments: this.commitments,
            proof: this.proofOfKnowledge
        }
    }

    /**
   * Generate Schnorr proof: PoK{a_0}
   * Proves knowledge of discrete log without revealing it
   */
    generateSchnorrProof (secret) {
    // k ← random scalar
        const k = randomScalar()

        // R = g^k
        const R = ed25519.Point.BASE.multiply(k)

        // A = g^secret (commitment to secret)
        const A = ed25519.Point.BASE.multiply(secret)

        // c = H(id || A || R)
        const idBytes = bigintToBytes(this.id)
        const ABytes = A.toBytes()
        const RBytes = R.toBytes()
        const challenge = hashToScalar(idBytes, ABytes, RBytes)

        // s = k + c * secret
        const s = modAdd(k, modMul(challenge, secret))

        return { R, s, A }
    }

    /**
   * Verify Schnorr proof from another participant
   */
    verifySchnorrProof (participantId, proof) {
        const { R, s, A } = proof

        // c = H(id || A || R)
        const idBytes = bigintToBytes(participantId)
        const ABytes = A.toBytes()
        const RBytes = R.toBytes()
        const challenge = hashToScalar(idBytes, ABytes, RBytes)

        // Verify: g^s = R + c*A
        const lhs = ed25519.Point.BASE.multiply(s)
        const rhs = R.add(A.multiply(challenge))

        return lhs.equals(rhs)
    }

    /**
   * Round 2: Generate shares for all participants
   * s_{i,j} = f_i(j) = ∑_{k=0}^{t-1} a_{i,k} * j^k
   */
    async round2_generateShares () {
        if (!this.coefficients) {
            throw new Error('Coefficients not initialized')
        }

        const encryptedShares = new Map()

        for (let j = 1; j <= this.n; j++) {
            const recipientId = BigInt(j)

            // Evaluate polynomial at point j
            let share = 0n
            for (let k = 0; k < this.coefficients.length; k++) {
                const term = modMul(
                    this.coefficients[k],
                    modPow(recipientId, BigInt(k))
                )
                share = modAdd(share, term)
            }

            this.shares.set(recipientId, share)

            // Encrypt share for other participants
            if (recipientId !== this.id) {
                const recipientPublicKey = this.peerPublicKeys.get(recipientId)
                if (!recipientPublicKey || !this.x25519KeyPair) {
                    throw new Error('Peer public key or keypair not initialized')
                }
                const sharedSecret = await deriveSharedSecret(
                    this.x25519KeyPair.privateKey,
                    recipientPublicKey
                )

                const shareBytes = scalarToBytes(share)
                const encrypted = await encryptShare(sharedSecret, shareBytes)
                encryptedShares.set(recipientId, encrypted)
            }
        }

        return encryptedShares
    }

    /**
   * Receive and decrypt share from another participant
   */
    async receiveShare (fromId, encryptedShare, commitments) {
        const senderId = BigInt(fromId)
        const senderPublicKey = this.peerPublicKeys.get(senderId)

        const sharedSecret = await deriveSharedSecret(
            this.x25519KeyPair.privateKey,
            senderPublicKey
        )

        const decrypted = await decryptShare(sharedSecret, encryptedShare)
        const share = bytesToNumberLE(decrypted)

        this.receivedShares.set(senderId, { share, commitments })
    }

    /**
   * Round 3: Verify received share using commitments
   * Verify: g^{s_{i,j}} = ∏_{k=0}^{t-1} C_{i,k}^{j^k}
   */
    verifyShare (fromId) {
        const senderId = BigInt(fromId)
        const data = this.receivedShares.get(senderId)
        if (!data) return false

        const { share, commitments } = data

        // LHS: g^share
        const lhs = ed25519.Point.BASE.multiply(share)

        // RHS: ∏_{k=0}^{t-1} C_k^{id^k}
        let rhs = ed25519.Point.ZERO
        for (let k = 0; k < commitments.length; k++) {
            const exponent = modPow(this.id, BigInt(k))
            const term = commitments[k].multiply(exponent)
            rhs = rhs.add(term)
        }

        return lhs.equals(rhs)
    }

    /**
   * Compute final secret share
   * s_i = ∑_{j=1}^{n} s_{j,i}
   */
    computeSecretShare () {
        let secretShare = 0n

        // Add own share
        secretShare = modAdd(secretShare, this.shares.get(this.id))

        // Add all received shares
        for (const [_, data] of this.receivedShares) {
            secretShare = modAdd(secretShare, data.share)
        }

        this.secretShare = secretShare
        return secretShare
    }

    /**
   * Compute verification share (public key share)
   * Y_i = g^{s_i}
   */
    computeVerificationShare () {
        if (this.secretShare === null) {
            throw new Error('Secret share not computed')
        }

        this.verificationShare = ed25519.Point.BASE.multiply(this.secretShare)
        return this.verificationShare
    }

    /**
   * Compute group public key
   * Y = ∏_{i=1}^{n} C_{i,0}
   */
    computeGroupPublicKey (allCommitments) {
        let groupKey = ed25519.Point.ZERO

        for (const commitments of allCommitments) {
            groupKey = groupKey.add(commitments[0])
        }

        this.publicKey = groupKey
        return groupKey
    }

    /**
   * Export state for inspection
   */
    exportState () {
        return {
            id: this.id.toString(),
            threshold: this.threshold,
            n: this.n,
            secretShare: this.secretShare?.toString(),
            verificationShare: this.verificationShare?.toHex(),
            publicKey: this.publicKey?.toHex()
        }
    }
}

/**
 * FROST DKG Protocol Coordinator
 */
export class FrostDKG {
    public threshold:number
    public n:number
    public participants:FrostParticipant[]
    public commitments:Map<bigint, any>
    public groupPublicKey:any

    constructor (threshold, totalParticipants) {
        if (threshold < 2) {
            throw new Error('Threshold must be at least 2')
        }
        if (threshold > totalParticipants) {
            throw new Error('Threshold cannot exceed total participants')
        }

        this.threshold = threshold
        this.n = totalParticipants
        this.participants = []
        this.commitments = new Map()
        this.groupPublicKey = null
    }

    /**
   * Initialize all participants with encryption keys
   */
    async initialize () {
    // Create participants
        for (let i = 1; i <= this.n; i++) {
            const participant = new FrostParticipant(i, this.threshold, this.n)
            this.participants.push(participant)
        }

        // Initialize X25519 keys
        const publicKeys = new Map()
        for (const p of this.participants) {
            const pubKey = await p.initialize()
            publicKeys.set(p.id, pubKey)
        }

        // Distribute public keys
        for (const p of this.participants) {
            for (const [id, pubKey] of publicKeys) {
                if (id !== p.id) {
                    await p.registerPeerKey(id, pubKey)
                }
            }
        }
    }

    /**
   * Execute Round 1: Generate commitments and proofs
   */
    async executeRound1 () {
        for (const p of this.participants) {
            const data = await p.round1_generateCommitments()
            this.commitments.set(p.id, data)

            // Verify proof of knowledge
            const valid = p.verifySchnorrProof(p.id, data.proof)
            if (!valid) {
                throw new Error(`Invalid proof of knowledge from participant ${p.id}`)
            }
        }
    }

    /**
   * Execute Round 2: Generate and exchange shares
   */
    async executeRound2 () {
    // Generate shares
        const allShares = new Map()
        for (const p of this.participants) {
            const shares = await p.round2_generateShares()
            allShares.set(p.id, shares)
        }

        // Distribute shares
        for (const sender of this.participants) {
            const shares = allShares.get(sender.id)
            const commitments = this.commitments.get(sender.id).commitments

            for (const receiver of this.participants) {
                if (sender.id !== receiver.id) {
                    const encryptedShare = shares.get(receiver.id)
                    await receiver.receiveShare(sender.id, encryptedShare, commitments)
                }
            }
        }
    }

    /**
   * Execute Round 3: Verify shares and compute keys
   */
    async executeRound3 () {
    // Verify all shares
        for (const p of this.participants) {
            for (const [fromId, _] of p.receivedShares) {
                const valid = p.verifyShare(fromId)
                if (!valid) {
                    throw new Error(`Invalid share from ${fromId} to ${p.id}`)
                }
            }
        }

        // Compute secret shares
        for (const p of this.participants) {
            p.computeSecretShare()
            p.computeVerificationShare()
        }

        // Compute group public key
        const allCommitments = Array.from(this.commitments.values()).map(d => d.commitments)
        this.groupPublicKey = this.participants[0].computeGroupPublicKey(allCommitments)

        // All participants should compute the same group key
        for (const p of this.participants) {
            p.computeGroupPublicKey(allCommitments)
        }
    }

    /**
   * Run complete DKG protocol
   */
    async run () {
        await this.initialize()
        await this.executeRound1()
        await this.executeRound2()
        await this.executeRound3()

        return {
            threshold: this.threshold,
            n: this.n,
            participants: this.participants.map(p => p.exportState()),
            groupPublicKey: this.groupPublicKey.toHex()
        }
    }
}

// Re-export ed25519 for tests
export { ed25519 }
