import { type Signal, signal, batch } from '@preact/signals'
import {
    type Commitment,
    FrostParticipant,
    type ParticipantState
} from '../src/participant.js'
import {
    type FrostSignature,
    FrostSigner,
    aggregateSignatures,
    verifySignature,
} from '../src/signing.js'
import { type EdwardsPoint } from '../src/index.js'
// import Debug from '@substrate-system/debug'
// const debug = Debug(import.meta.env.DEV)

export interface ParticipantBox {
    id:number;
    generated:boolean;
    participant:FrostParticipant|null;
    commitment:Commitment|null;
}

export interface DKGResult {
    threshold:number;
    n:number;
    participants:ParticipantState[];
    groupPublicKey:EdwardsPoint;
}

export interface SigningState {
    selectedParticipants:Set<string>
    message:string
    signature:FrostSignature|null
    verificationResult:boolean|null
    signing:boolean
}

export function State ():{
    threshold:Signal<number>
    total:Signal<number>
    loading:Signal<boolean>
    result:Signal<DKGResult|null>
    error:Signal<string|null>
    signing:Signal<SigningState>
    participantBoxes:Signal<ParticipantBox[]>
    allGenerated:Signal<boolean>
    participants:Signal<FrostParticipant[]>
    groupPublicKey:Signal<EdwardsPoint|null>
    proofsVerified:Signal<boolean>
    sharesVerified:Signal<boolean>
} {  // eslint-disable-line indent
    const state = {
        threshold: signal<number>(3),
        total: signal<number>(5),
        loading: signal<boolean>(false),
        result: signal<DKGResult | null>(null),
        error: signal<string | null>(null),
        signing: signal<SigningState>({
            selectedParticipants: new Set(),
            message: '',
            signature: null,
            verificationResult: null,
            signing: false
        }),
        participantBoxes: signal<ParticipantBox[]>(
            Array.from({ length: 5 }, (_, i) => ({
                id: i + 1,
                generated: false,
                participant: null,
                commitment: null
            }))
        ),
        allGenerated: signal<boolean>(false),
        participants: signal<FrostParticipant[]>([]),
        groupPublicKey: signal<EdwardsPoint | null>(null),
        proofsVerified: signal<boolean>(false),
        sharesVerified: signal<boolean>(false)
    }

    // @ts-expect-error dev
    window.state = state

    return state
}

State.setThreshold = function (state:ReturnType<typeof State>, value:number) {
    state.threshold.value = value
}

State.setTotal = function (state:ReturnType<typeof State>, value:number) {
    state.total.value = value
    // Reset participant boxes when total changes
    state.participantBoxes.value = Array.from({ length: value }, (_, i) => ({
        id: i + 1,
        generated: false,
        participant: null,
        commitment: null
    }))
    state.result.value = null
    state.allGenerated.value = false
}

/**
 * Initialize participant boxes
 */
State.initializeBoxes = function (state:ReturnType<typeof State>) {
    const n = state.total.value
    state.participantBoxes.value = Array.from({ length: n }, (_, i) => ({
        id: i + 1,
        generated: false,
        participant: null,
        commitment: null
    }))
    state.result.value = null
    state.allGenerated.value = false
    state.error.value = null
}

/**
 * Generate a single participant's shard
 */
State.generateShard = async function (
    state:ReturnType<typeof State>,
    participantId:number
) {
    const threshold = state.threshold.value
    const n = state.total.value

    if (threshold < 2) {
        state.error.value = 'Threshold must be at least 2'
        return
    }

    if (threshold > n) {
        state.error.value = 'Threshold cannot exceed total participants'
        return
    }

    try {
        // Create and initialize this participant
        const participant = await FrostParticipant.init(
            participantId,
            threshold,
            n
        )

        // Generate commitments immediately so we have the polynomial
        const commitment = await participant.round1_generateCommitments()

        // Update the visual box
        const boxes = [...state.participantBoxes.value]
        const box = boxes.find(b => b.id === participantId)
        if (box) {
            box.generated = true
            box.participant = participant
            box.commitment = commitment
        }
        state.participantBoxes.value = boxes

        // Check if all are generated
        const allGenerated = boxes.every(b => b.generated)
        state.allGenerated.value = allGenerated
    } catch (err) {
        state.error.value = (err as Error).message
    }
}

/**
 * Verify Schnorr proofs of all participants
 */
State.verifyProofs = async function (state:ReturnType<typeof State>) {
    try {
        state.error.value = null

        for (const box of state.participantBoxes.value) {
            if (!box.commitment || !box.participant) {
                throw new Error(`Participant ${box.id} not ready`)
            }

            const valid = box.participant.verifySchnorrProof(
                box.commitment.participantId,
                box.commitment.proof
            )
            if (!valid) {
                throw new Error(`Invalid proof from participant ${box.id}`)
            }
        }

        state.proofsVerified.value = true
    } catch (err) {
        state.error.value = (err as Error).message
        state.proofsVerified.value = false
    }
}

/**
 * Verify all shares between participants
 */
State.verifyShares = async function (state:ReturnType<typeof State>) {
    try {
        state.error.value = null

        // Get participants
        const participants:FrostParticipant[] = []
        for (const box of state.participantBoxes.value) {
            if (!box.participant) {
                throw new Error(`Participant ${box.id} not generated`)
            }
            participants.push(box.participant)
        }

        // Register peer keys if not done
        const publicKeys = new Map<bigint, ArrayBuffer>()
        for (const p of participants) {
            const pubKey = await p.getPublicKey()
            publicKeys.set(p.id, pubKey)
        }

        for (const p of participants) {
            for (const [id, pubKey] of publicKeys) {
                if (id !== p.id) {
                    await p.registerPeerKey(Number(id), pubKey)
                }
            }
        }

        // Get commitments
        const commitments = new Map<bigint, Commitment>()
        for (const box of state.participantBoxes.value) {
            if (!box.commitment) {
                throw new Error(`No commitment for participant ${box.id}`)
            }
            commitments.set(box.commitment.participantId, box.commitment)
        }

        // Generate and distribute shares
        const allShares = new Map<bigint, Map<bigint, Uint8Array>>()
        for (const p of participants) {
            const shares = await p.round2_generateShares()
            allShares.set(p.id, shares)
        }

        for (const sender of participants) {
            const shares = allShares.get(sender.id)!
            const senderCommitments = commitments.get(sender.id)!.commitments

            for (const receiver of participants) {
                if (sender.id !== receiver.id) {
                    const encryptedShare = shares.get(receiver.id)!
                    await receiver.receiveShare(
                        sender.id,
                        encryptedShare,
                        senderCommitments
                    )
                }
            }
        }

        // Verify all shares
        for (const p of participants) {
            for (const [fromId, _] of p.receivedShares) {
                const valid = p.verifyShare(fromId)
                if (!valid) {
                    throw new Error(`Invalid share from ${fromId} to ${p.id}`)
                }
            }
        }

        state.sharesVerified.value = true
        state.participants.value = participants
    } catch (err) {
        state.error.value = (err as Error).message
        state.sharesVerified.value = false
    }
}

/**
 * Complete key generation after proofs and shares are verified
 */
State.completeKeyGeneration = async function (state:ReturnType<typeof State>) {
    if (!state.proofsVerified.value) {
        state.error.value = 'Proofs must be verified first'
        return
    }

    if (!state.sharesVerified.value) {
        state.error.value = 'Shares must be verified first'
        return
    }

    try {
        state.error.value = null
        state.loading.value = true

        const threshold = state.threshold.value
        const n = state.total.value
        const participants = state.participants.value

        // Get commitments
        const commitments = new Map<bigint, Commitment>()
        for (const box of state.participantBoxes.value) {
            if (!box.commitment) {
                throw new Error(`No commitment for participant ${box.id}`)
            }
            commitments.set(box.commitment.participantId, box.commitment)
        }

        // Compute secret shares and verification shares
        for (const p of participants) {
            p.computeSecretShare()
            p.computeVerificationShare()
        }

        // Compute group public key
        const allCommitments = Array.from(commitments.values())
            .map((d:Commitment) => d.commitments)
        const groupPublicKey = participants[0].computeGroupPublicKey(allCommitments)

        for (const p of participants) {
            p.computeGroupPublicKey(allCommitments)
        }

        const res = {
            threshold,
            n,
            participants: participants.map(p => p.exportState()),
            groupPublicKey
        }

        batch(() => {
            state.result.value = res
            state.groupPublicKey.value = groupPublicKey
            // Reset signing state
            state.signing.value = {
                selectedParticipants: new Set(),
                message: '',
                signature: null,
                verificationResult: null,
                signing: false
            }
        })
    } catch (err) {
        state.error.value = (err as Error).message
    } finally {
        state.loading.value = false
    }
}

State.toggleParticipant = function (
    state:ReturnType<typeof State>,
    participantId:string
) {
    const newSelected = new Set(state.signing.value.selectedParticipants)
    if (newSelected.has(participantId)) {
        newSelected.delete(participantId)
    } else {
        newSelected.add(participantId)
    }
    state.signing.value = {
        ...state.signing.value,
        selectedParticipants: newSelected,
        signature: null,
        verificationResult: null
    }
}

State.setMessage = function (state:ReturnType<typeof State>, message:string) {
    state.signing.value = {
        ...state.signing.value,
        message,
        signature: null,
        verificationResult: null
    }
}

/**
 * Use the shards to sign a message.
 */
State.signMessage = async function (state:ReturnType<typeof State>):Promise<void> {
    const participants = state.participants.value
    const result = state.result.value
    if (!participants.length || !result) {
        state.error.value = 'No DKG result available'
        return
    }

    const selectedIds = Array.from(state.signing.value.selectedParticipants)
    if (selectedIds.length < result.threshold) {
        state.error.value = `Need at least ${result.threshold} participants to sign`
        return
    }

    state.signing.value = { ...state.signing.value, signing: true }
    state.error.value = null

    try {
        const message = state.signing.value.message

        // Create signers from selected participants
        const signers:FrostSigner[] = []
        const signerIds:bigint[] = []

        for (const idStr of selectedIds) {
            const participant = participants.find(p => p.id.toString() === idStr)
            if (
                !participant ||
                !participant.secretShare ||
                !participant.verificationShare
            ) {
                throw new Error(`Invalid participant ${idStr}`)
            }

            // Build verification shares map for Lagrange interpolation
            const verificationShares = new Map<bigint, EdwardsPoint>()
            for (const p of participants) {
                if (p.verificationShare) {
                    verificationShares.set(p.id, p.verificationShare)
                }
            }

            const signer = new FrostSigner(
                participant.id,
                participant.secretShare,
                participant.verificationShare,
                participant.publicKey!,
                verificationShares
            )
            signers.push(signer)
            signerIds.push(participant.id)
        }

        // Round 1: Generate commitments
        const commitments = signers.map(s => s.generateCommitment())

        // Round 2: Generate signature shares
        const signatureShares = signers.map(s =>
            s.generateSignatureShare(message, commitments, signerIds)
        )

        // Aggregate signature
        const signature = aggregateSignatures(
            message,
            commitments,
            signatureShares,
        )

        state.signing.value = {
            ...state.signing.value,
            signature,
            signing: false
        }

        // Auto-verify
        State.verifySignature(state)
    } catch (err) {
        state.error.value = (err as Error).message
        state.signing.value = { ...state.signing.value, signing: false }
    }
}

State.verifySignature = function (state:ReturnType<typeof State>) {
    const result = state.result.value
    const sigBytes = state.signing.value.signature
    const message = state.signing.value.message

    if (!result || !sigBytes || !message) {
        state.error.value = 'Missing signature or message'
        return
    }

    try {
        const groupPublicKey = result.groupPublicKey
        const sig = state.signing.value.signature!
        const valid = verifySignature(message, sig, groupPublicKey)

        state.signing.value = {
            ...state.signing.value,
            verificationResult: valid
        }
    } catch (err) {
        state.error.value = (err as Error).message
    }
}
