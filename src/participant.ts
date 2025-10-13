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
    bytesToNumberLE,
    publicKey as getPublicKey
} from './util.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { type EdwardsPoint } from '@noble/curves/abstract/edwards.js'

export type ParticipantState = {
    id:string;
    threshold:number;
    n:number;
    secretShare?:string;
    verificationShare?:string;
    publicKey:string
}

export type SchnorrProof = {
    R:EdwardsPoint,
    s:bigint,
    A:EdwardsPoint
}

export type ReceivedShare = {
    share:bigint;
    commitments:EdwardsPoint[];
}

export type Commitment = {
    participantId:bigint;
    commitments:EdwardsPoint[];
    proof:SchnorrProof;
}

/**
 * FROST DKG Participant
 */
export class FrostParticipant {
    id:bigint
    threshold:number
    n:number
    coefficients:bigint[]|null
    commitments:EdwardsPoint[]|null
    proofOfKnowledge:SchnorrProof|null
    x25519KeyPair:CryptoKeyPair|null
    peerPublicKeys:Map<bigint, CryptoKey>
    shares:Map<bigint, bigint>
    receivedShares:Map<bigint, ReceivedShare>
    secretShare:bigint|null
    verificationShare:EdwardsPoint|null
    publicKey:EdwardsPoint|null

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
        this.peerPublicKeys = new Map<bigint, CryptoKey>()

        // Shares for other participants
        this.shares = new Map<bigint, bigint>()
        // Received shares from other participants
        this.receivedShares = new Map<bigint, ReceivedShare>()

        // Final results
        this.secretShare = null
        this.verificationShare = null
        this.publicKey = null
    }

    /**
     * Create and initialize a new FrostParticipant
     * @param id - Unique identifier for this participant (1-indexed)
     * @param threshold - Minimum number of participants needed for signing
     * @param totalParticipants - Total number of participants in the DKG
     * @returns {Promise<FrostParticipant>} Initialized participant
     */
    static async init (
        id:number,
        threshold:number,
        totalParticipants:number
    ):Promise<FrostParticipant> {
        const participant = new FrostParticipant(id, threshold, totalParticipants)
        participant.x25519KeyPair = await generateX25519KeyPair()
        return participant
    }

    /**
     * Get X25519 public key for encrypted channels
     * @returns {Promise<ArrayBuffer>} The public key
     */
    async getPublicKey ():Promise<ArrayBuffer> {
        if (!this.x25519KeyPair) {
            throw new Error('Participant not initialized')
        }

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
    async round1_generateCommitments ():Promise<Commitment> {
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
    generateSchnorrProof (secret:bigint):SchnorrProof {
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
    verifySchnorrProof (participantId:bigint, proof:SchnorrProof) {
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
    async round2_generateShares ():Promise<Map<bigint, Uint8Array<ArrayBuffer>>> {
        if (!this.coefficients) {
            throw new Error('Coefficients not initialized')
        }

        const encryptedShares = new Map<bigint, Uint8Array<ArrayBuffer>>()

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
     * Receive and decrypt a share from another participant.
     */
    async receiveShare (
        fromId:number|bigint,
        encryptedShare:Uint8Array,
        commitments:EdwardsPoint[]
    ):Promise<void> {
        const senderId = BigInt(fromId)
        const senderPublicKey = this.peerPublicKeys.get(senderId)
        if (!senderPublicKey) {
            throw new Error(`No public key found for participant ${senderId}`)
        }

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
    verifyShare (fromId:number|bigint):boolean {
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
    computeSecretShare ():bigint {
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
    computeVerificationShare ():EdwardsPoint {
        if (this.secretShare === null) {
            throw new Error('Secret share not computed')
        }

        this.verificationShare = ed25519.Point.BASE.multiply(this.secretShare)
        return this.verificationShare
    }

    /**
     * Compute group public key
     * Y = ∏_{i=1}^{n} C_{i,0}
     *
     * @param {EdwardsPoint[][]} allCommitments All commitments (from all
     * participants) in this scheme.
     * @returns {EdwardsPoint} The Ed25519 public key.
     */
    static publicKey (allCommitments:EdwardsPoint[][]):EdwardsPoint {
        return getPublicKey(allCommitments)
    }

    /**
     * Compute and set this.publicKey.
     */
    computeGroupPublicKey (allCommitments:EdwardsPoint[][]):EdwardsPoint {
        this.publicKey = FrostParticipant.publicKey(allCommitments)
        return this.publicKey
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
            publicKey: this.publicKey?.toHex() ?? ''
        }
    }
}
