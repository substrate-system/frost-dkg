import { ed25519 } from '@noble/curves/ed25519.js'
import { type EdwardsPoint } from '@noble/curves/abstract/edwards.js'
import {
    FrostParticipant,
    type ParticipantState,
    type SchnorrProof
} from './participant.js'

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

export type CommitmentData = {
    participantId:bigint;
    commitments:EdwardsPoint[];
    proof:SchnorrProof;
}

/**
 * FROST DKG Protocol Coordinator
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

    /**
     * Initialize all participants with encryption keys
     */
    async initialize ():Promise<void> {
        // Create participants
        for (let i = 1; i <= this.n; i++) {
            const participant = new FrostParticipant(i, this.threshold, this.n)
            this.participants.push(participant)
        }

        // Initialize X25519 keys
        const publicKeys = new Map<bigint, ArrayBuffer>()
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
     * Execute Round 1: Generate commitments and proofs.
     * @returns {Promise<void>}
     */
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

    /**
     * Execute Round 2: Generate and exchange shares
     * @returns {Promise<void>}
     */
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

    /**
     * Execute Round 3: Verify shares and compute keys
     * @returns {Promise<void>}
     */
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

    /**
     * Run complete DKG protocol
     */
    async run ():Promise<{
        threshold:number;
        n:number;
        participants:ParticipantState[];
        groupPublicKey:string;
    }> {
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

// Re-export ed25519
export { ed25519 }
