import { type EdwardsPoint } from '@noble/curves/abstract/edwards.js'
import {
    FrostParticipant,
    type SchnorrProof
} from './participant.js'

/**
 * TEST HELPER ONLY - DO NOT USE IN PRODUCTION
 *
 * This simulates a distributed key generation in a single process.
 * This defeats the entire security model of FROST DKG where participants
 * should run on separate machines.
 *
 * Only use this for:
 * - Testing your application logic
 * - Understanding the protocol
 * - Demo purposes
 *
 * In production, each participant must run independently using FrostParticipant.
 */

export type CommitmentData = {
    participantId:bigint;
    commitments:EdwardsPoint[];
    proof:SchnorrProof;
}

/**
 * Simulates FROST DKG in a single process (FOR TESTING ONLY)
 *
 * WARNING: This creates all participants in one place, meaning the full
 * secret key material exists in one process. This is INSECURE and should
 * NEVER be used in production.
 */
export class FrostDKG {
    threshold:number
    n:number
    participants:FrostParticipant[]
    commitments:Map<bigint, CommitmentData>
    groupPublicKey:EdwardsPoint|null

    constructor (threshold:number, totalParticipants:number) {
        if (threshold < 2) {
            throw new Error('Threshold must be at least 2')
        }
        if (threshold > totalParticipants) {
            throw new Error('Threshold cannot exceed total participants')
        }

        this.threshold = threshold
        this.n = totalParticipants
        this.participants = []
        this.commitments = new Map<bigint, CommitmentData>()
        this.groupPublicKey = null
    }

    async initialize ():Promise<void> {
        // Create and initialize participants
        const publicKeys = new Map<bigint, ArrayBuffer>()
        for (let i = 1; i <= this.n; i++) {
            const participant = await FrostParticipant.init(i, this.threshold, this.n)
            const pubKey = await participant.getPublicKey()
            publicKeys.set(participant.id, pubKey)
            this.participants.push(participant)
        }

        // Distribute public keys
        for (const p of this.participants) {
            for (const [id, pubKey] of publicKeys) {
                if (id !== p.id) {
                    await p.registerPeerKey(Number(id), pubKey)
                }
            }
        }
    }

    async executeRound1 ():Promise<void> {
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

    async executeRound2 ():Promise<void> {
        // Generate shares
        const allShares = new Map<bigint, Map<bigint, Uint8Array>>()
        for (const p of this.participants) {
            const shares = await p.round2_generateShares()
            allShares.set(p.id, shares)
        }

        // Distribute shares
        for (const sender of this.participants) {
            const shares = allShares.get(sender.id)!
            const commitments = this.commitments.get(sender.id)!.commitments

            for (const receiver of this.participants) {
                if (sender.id !== receiver.id) {
                    const encryptedShare = shares.get(receiver.id)!
                    await receiver.receiveShare(sender.id, encryptedShare, commitments)
                }
            }
        }
    }

    async executeRound3 ():Promise<void> {
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
        const allCommitments = (Array.from(this.commitments.values())
            .map(d => d.commitments))
        this.groupPublicKey = (this.participants[0]
            .computeGroupPublicKey(allCommitments))

        // All participants should compute the same group key
        for (const p of this.participants) {
            p.computeGroupPublicKey(allCommitments)
        }
    }
}
