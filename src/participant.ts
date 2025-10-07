import {
    generateX25519KeyPair,
    randomScalar,
    bigintToBytes,
    hashToScalar,
    modAdd,
    modMul,
    modPow,
    deriveSharedSecret,
    scalarToBytes,
    encryptShare,
    decryptShare,
    bytesToNumberLE
} from './util.js'
import { ed25519 } from '@noble/curves/ed25519.js'

export type ParticipantState = {
    id:string;
    threshold:number;
    n:number;
    secretShare?:string;
    verificationShare:string;
    publicKey:string
}

/**
 * FROST DKG Participant
 */
export class FrostParticipant {
    id:bigint
    threshold:number
    n:number
    coefficients:bigint[]|null
    commitments:any[]|null
    proofOfKnowledge:any
    x25519KeyPair:CryptoKeyPair|null
    peerPublicKeys:Map<bigint, any>
    shares:Map<bigint, bigint>
    receivedShares:Map<bigint, any>
    secretShare:bigint|null
    verificationShare:any
    publicKey:any

    constructor (id:number, threshold:number, totalParticipants:number) {
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
     * @returns {Promise<ArrayBuffer>} The public key
     */
    async initialize ():Promise<ArrayBuffer> {
        this.x25519KeyPair = await generateX25519KeyPair()

        return await crypto.subtle.exportKey(
            'raw',
            this.x25519KeyPair.publicKey
        )
    }

    /**
     * Register peer's X25519 public key
     */
    async registerPeerKey (
        peerId:number,
        publicKeyBytes:ArrayBuffer
    ):Promise<void> {
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
    async round1_generateCommitments ():Promise<void> {
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
    async receiveShare (fromId:number|bigint, encryptedShare, commitments) {
        const senderId = BigInt(fromId)
        const senderPublicKey = this.peerPublicKeys.get(senderId)

        const sharedSecret = await deriveSharedSecret(
            this.x25519KeyPair!.privateKey,
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
    exportState ():ParticipantState {
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
