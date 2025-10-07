/**
 * FROST DKG - Distributed Key Generation for Threshold Signatures
 *
 * This library implements the FROST (Flexible Round-Optimized Schnorr
 * Threshold) DKG protocol for generating threshold signature keys across
 * multiple participants.
 *
 * IMPORTANT: Each participant should run on a SEPARATE machine. The security
 * of FROST DKG relies on the fact that no single party ever knows the complete
 * private key.
 *
 * @example
 * ```ts
 * import { FrostParticipant } from '@substrate-system/frost-dkg'
 *
 * // On machine 1
 * const participant = await FrostParticipant.init(1, 3, 5)
 * const myPublicKey = await participant.getPublicKey()
 *
 * // >> Send myPublicKey to other participants via network <<
 * // << Receive their public keys <<
 *
 * await participant.registerPeerKey(2, publicKey2)
 * // ... continue with DKG rounds
 * ```
 */

export { FrostParticipant, type ParticipantState } from './participant.js'
export {
    FrostSigner,
    aggregateSignatures,
    verifySignature,
    decodeHex,
    type SigningCommitment,
    type SignatureShare,
    type FrostSignature
} from './signing.js'
export { signatureToHex, signatureToU8Array } from './util.js'
export type { EdwardsPoint } from '@noble/curves/abstract/edwards.js'
export { ed25519 } from '@noble/curves/ed25519.js'
