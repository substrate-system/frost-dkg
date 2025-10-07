import { ed25519 } from '@noble/curves/ed25519.js'
import { type EdwardsPoint } from '@noble/curves/abstract/edwards.js'
import {
    randomScalar,
    hashToScalar,
    modAdd,
    modMul,
    bigintToBytes,
    modInverse,
} from './util.js'

/**
 * FROST Threshold Signing Implementation
 * Based on FROST paper: https://eprint.iacr.org/2020/852.pdf
 */

export type SigningCommitment = {
    participantId:bigint;
    // Hiding nonce commitment
    D:EdwardsPoint;
    // Binding nonce commitment
    E:EdwardsPoint;
}

export type SignatureShare = {
    participantId:bigint;
    z:bigint;
}

export type FrostSignature = {
    R:EdwardsPoint;
    z:bigint;
}

/**
 * Signer participant in FROST signing protocol
 */
export class FrostSigner {
    id:bigint
    secretShare:bigint
    verificationShare:EdwardsPoint
    groupPublicKey:EdwardsPoint
    // All verification shares from DKG (for Lagrange interpolation)
    verificationShares:Map<bigint, EdwardsPoint>

    // Signing state
    hidingNonce:bigint|null = null
    bindingNonce:bigint|null = null
    commitment:SigningCommitment|null = null

    constructor (
        id:bigint,
        secretShare:bigint,
        verificationShare:EdwardsPoint,
        groupPublicKey:EdwardsPoint,
        verificationShares:Map<bigint, EdwardsPoint>
    ) {
        this.id = id
        this.secretShare = secretShare
        this.verificationShare = verificationShare
        this.groupPublicKey = groupPublicKey
        this.verificationShares = verificationShares
    }

    /**
     * Round 1: Generate nonces and commitments
     */
    generateCommitment ():SigningCommitment {
        // Generate two random nonces
        this.hidingNonce = randomScalar()
        this.bindingNonce = randomScalar()

        // D = g^d (hiding commitment)
        const D = ed25519.Point.BASE.multiply(this.hidingNonce)

        // E = g^e (binding commitment)
        const E = ed25519.Point.BASE.multiply(this.bindingNonce)

        this.commitment = {
            participantId: this.id,
            D,
            E
        }

        return this.commitment
    }

    /**
     * Round 2: Generate signature share
     * @param message - The message to sign
     * @param commitments - All commitments from signing participants
     * @param signerIds - IDs of all participants in this signing session
     */
    generateSignatureShare (
        message:string,
        commitments:SigningCommitment[],
        signerIds:bigint[]
    ):SignatureShare {
        if (!this.hidingNonce || !this.bindingNonce) {
            throw new Error('Commitments not generated')
        }

        // Compute binding values for each participant
        const bindingFactors = this.computeBindingFactors(
            commitments,
            message
        )

        // Compute group commitment R
        const R = this.computeGroupCommitment(commitments, bindingFactors)

        // Compute challenge c = H(R || Y || m)
        const challenge = this.computeChallenge(R, message)

        // Compute Lagrange coefficient for this participant
        const lambda = this.computeLagrangeCoefficient(this.id, signerIds)

        // Get binding factor for this participant
        const rho = bindingFactors.get(this.id)!

        // Compute signature share: z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c)
        const z = modAdd(
            this.hidingNonce,
            modAdd(
                modMul(this.bindingNonce, rho),
                modMul(modMul(lambda, this.secretShare), challenge)
            )
        )

        return {
            participantId: this.id,
            z
        }
    }

    /**
     * Compute binding factors for all participants
     * rho_i = H(i || msg || B)
     * where B is the encoded list of all commitments
     */
    computeBindingFactors (
        commitments:SigningCommitment[],
        message:string
    ):Map<bigint, bigint> {
        const bindingFactors = new Map<bigint, bigint>()

        // Encode all commitments
        const commitmentsEncoded = commitments
            .sort((a, b) => Number(a.participantId - b.participantId))
            .flatMap(c => [
                ...c.D.toBytes(),
                ...c.E.toBytes()
            ])

        const msgBytes = new TextEncoder().encode(message)

        for (const commitment of commitments) {
            const idBytes = bigintToBytes(commitment.participantId)
            const rho = hashToScalar(
                idBytes,
                msgBytes,
                new Uint8Array(commitmentsEncoded)
            )
            bindingFactors.set(commitment.participantId, rho)
        }

        return bindingFactors
    }

    /**
     * Compute group commitment R
     * R = ∏(D_i * E_i^{rho_i})
     */
    computeGroupCommitment (
        commitments:SigningCommitment[],
        bindingFactors:Map<bigint, bigint>
    ):EdwardsPoint {
        let R = ed25519.Point.ZERO

        for (const commitment of commitments) {
            const rho = bindingFactors.get(commitment.participantId)!
            // D_i * E_i^{rho_i}
            const term = commitment.D.add(commitment.E.multiply(rho))
            R = R.add(term)
        }

        return R
    }

    /**
     * Compute challenge
     * c = H(R || Y || m)
     */
    computeChallenge (R:EdwardsPoint, message:string):bigint {
        const RBytes = R.toBytes()
        const YBytes = this.groupPublicKey.toBytes()
        const msgBytes = new TextEncoder().encode(message)

        return hashToScalar(RBytes, YBytes, msgBytes)
    }

    /**
     * Compute Lagrange coefficient for participant i
     * λ_i = ∏_{j∈S,j≠i} j/(j-i)
     * where S is the set of signer IDs
     */
    computeLagrangeCoefficient (
        id:bigint,
        signerIds:bigint[]
    ):bigint {
        let numerator = 1n
        let denominator = 1n

        for (const j of signerIds) {
            if (j === id) continue

            numerator = modMul(numerator, j)
            denominator = modMul(denominator, modAdd(j, -id))
        }

        // λ = numerator * denominator^{-1}
        return modMul(numerator, modInverse(denominator))
    }
}

/**
 * Aggregate signature shares into final signature
 */
export function aggregateSignatures (
    message:string,
    commitments:SigningCommitment[],
    signatureShares:SignatureShare[],
):FrostSignature {
    // Recompute binding factors
    const msgBytes = new TextEncoder().encode(message)
    const commitmentsEncoded = commitments
        .sort((a, b) => Number(a.participantId - b.participantId))
        .flatMap(c => [
            ...c.D.toBytes(),
            ...c.E.toBytes()
        ])

    const bindingFactors = new Map<bigint, bigint>()
    for (const commitment of commitments) {
        const idBytes = bigintToBytes(commitment.participantId)
        const rho = hashToScalar(
            idBytes,
            msgBytes,
            new Uint8Array(commitmentsEncoded)
        )
        bindingFactors.set(commitment.participantId, rho)
    }

    // Compute group commitment R
    let R = ed25519.Point.ZERO
    for (const commitment of commitments) {
        const rho = bindingFactors.get(commitment.participantId)!
        const term = commitment.D.add(commitment.E.multiply(rho))
        R = R.add(term)
    }

    // Aggregate signature shares: z = ∑ z_i
    let z = 0n
    for (const share of signatureShares) {
        z = modAdd(z, share.z)
    }

    return { R, z }
}

/**
 * Verify a FROST signature
 */
export function verifySignature (
    message:string,
    signature:FrostSignature,
    groupPublicKey:EdwardsPoint
):boolean {
    const { R, z } = signature

    // Compute challenge c = H(R || Y || m)
    const RBytes = R.toBytes()
    const YBytes = groupPublicKey.toBytes()
    const msgBytes = new TextEncoder().encode(message)
    const challenge = hashToScalar(RBytes, YBytes, msgBytes)

    // Verify: g^z = R + c*Y
    const lhs = ed25519.Point.BASE.multiply(z)
    const rhs = R.add(groupPublicKey.multiply(challenge))

    return lhs.equals(rhs)
}

/**
 * Decode signature from hex string
 */
export function decodeHex (hex:string):FrostSignature {
    if (hex.length !== 128) {
        throw new Error('Invalid signature length')
    }

    const bytes = new Uint8Array(64)
    for (let i = 0; i < 64; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }

    const RBytes = bytes.slice(0, 32)
    const zBytes = bytes.slice(32, 64)

    const R = ed25519.Point.fromHex(Array.from(RBytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(''))

    let z = 0n
    for (let i = 0; i < 32; i++) {
        z |= BigInt(zBytes[i]) << BigInt(i * 8)
    }

    return { R, z }
}
