import { test } from '@substrate-system/tapzero'
import { bytesToNumberLE } from '@noble/curves/utils.js'
import {
    randomScalar,
    scalarToBytes,
    deriveSharedSecret,
    encryptShare,
    decryptShare
} from '../src/util.js'
import { type Commitment, FrostParticipant } from '../src/participant.js'
import { ed25519 } from '../src/index.js'
import {
    FrostSigner,
    aggregateSignatures,
    verifySignature
} from '../src/signing.js'
import type { EdwardsPoint } from '@noble/curves/abstract/edwards.js'

test('proof of knowledge', async t => {
    const participant = await FrostParticipant.init(3, 5, 1)

    // Generate commitment
    const { proof } = await participant.round1_generateCommitments()

    // Verify proof
    const valid = participant.verifySchnorrProof(participant.id, proof)
    t.ok(valid, 'valid proof should be accepted')

    // Try with wrong proof
    const fakeProof = {
        R: ed25519.Point.BASE.multiply(randomScalar()),
        s: randomScalar(),
        A: proof.A
    }
    const invalid = participant.verifySchnorrProof(participant.id, fakeProof)
    t.ok(!invalid, 'invalid proof should be rejected')
})

test('share encryption', async t => {
    // Initialize two participants
    const p1 = await FrostParticipant.init(3, 5, 1)
    const p2 = await FrostParticipant.init(3, 5, 2)

    // Exchange public keys
    const p1PubKey = await p1.getPublicKey()
    const p2PubKey = await p2.getPublicKey()
    await p1.registerPeerKey(2, p2PubKey)
    await p2.registerPeerKey(1, p1PubKey)

    // Test encryption/decryption
    const testShare = randomScalar()
    const testBytes = scalarToBytes(testShare)

    const p1PeerKey = p1.peerPublicKeys.get(p2.id)!
    const secret1 = await deriveSharedSecret(
        p1.x25519KeyPair!.privateKey,
        p1PeerKey
    )

    const encrypted = await encryptShare(secret1, testBytes)

    const p2PeerKey = p2.peerPublicKeys.get(p1.id)!
    const secret2 = await deriveSharedSecret(
        p2.x25519KeyPair!.privateKey,
        p2PeerKey
    )

    const decrypted = await decryptShare(secret2, encrypted)
    const recoveredShare = bytesToNumberLE(decrypted)

    t.equal(testShare, recoveredShare,
        'encryption/decryption should work correctly')
})

test('basic DKG (3-of-5)', async t => {
    const { participants } = await runDKG(3, 5)

    // Verify all participants have the same group public key
    const firstPubKey = participants[0].publicKey!.toHex()
    for (const p of participants) {
        t.equal(
            p.publicKey!.toHex(),
            firstPubKey,
            `participant ${p.id} should have same group public key`
        )
    }

    // Verify verification shares are valid
    for (const p of participants) {
        if (!p.secretShare) {
            t.fail(`participant ${p.id} has no secret share`)
            continue
        }
        const computed = ed25519.Point.BASE.multiply(p.secretShare)
        t.ok(
            computed.equals(p.verificationShare!),
            `participant ${p.id} should have valid verification share`
        )
    }
})

test('minimal threshold (2-of-3)', async t => {
    const { participants, threshold, n } = await runDKG(2, 3)

    t.equal(threshold, 2, 'should have correct threshold')
    t.equal(n, 3, 'should have correct number of participants')
    t.equal(participants.length, 3,
        'should have correct number of participant objects')
})

test('share verification', async t => {
    // Initialize participants
    const participants:FrostParticipant[] = []
    const publicKeys = new Map<bigint, ArrayBuffer>()

    for (let i = 1; i <= 5; i++) {
        const participant = await FrostParticipant.init(3, 5, i)
        const pubKey = await participant.getPublicKey()
        publicKeys.set(participant.id, pubKey)
        participants.push(participant)
    }

    // Distribute public keys
    for (const p of participants) {
        for (const [id, pubKey] of publicKeys) {
            if (id !== p.id) {
                await p.registerPeerKey(Number(id), pubKey)
            }
        }
    }

    // Round 1: Generate commitments
    const commitments = new Map<bigint, { participantId:bigint, commitments:EdwardsPoint[], proof:any }>()
    for (const p of participants) {
        const data = await p.round1_generateCommitments()
        commitments.set(p.id, data)
    }

    // Round 2: Generate and distribute shares
    const allShares = new Map<bigint, Map<bigint, Uint8Array>>()
    for (const p of participants) {
        const shares = await p.round2_generateShares()
        allShares.set(p.id, shares)
    }

    // Distribute shares
    for (const sender of participants) {
        const shares = allShares.get(sender.id)!
        const senderCommitments = commitments.get(sender.id)!.commitments

        for (const receiver of participants) {
            if (sender.id !== receiver.id) {
                const encryptedShare = shares.get(receiver.id)!
                await receiver.receiveShare(sender.id, encryptedShare, senderCommitments)
            }
        }
    }

    // All shares should verify correctly
    for (const p of participants) {
        for (const [fromId, _] of p.receivedShares) {
            const valid = p.verifyShare(fromId)
            t.ok(valid, `share from ${fromId} to ${p.id} should verify`)
        }
    }
})

test('polynomial reconstruction', async t => {
    const { participants, groupPublicKey } = await runDKG(3, 5)

    // Verify that all participants computed the same group public key
    for (const p of participants) {
        t.ok(p.publicKey!.equals(groupPublicKey),
            `participant ${p.id} computed correct group public key`)
    }
})

test('edge cases', async t => {
    // Test minimum configuration
    await runDKG(2, 2)
    t.ok(true, '2-of-2 configuration should work')

    // Test larger configuration
    await runDKG(5, 7)
    t.ok(true, '5-of-7 configuration should work')

    // Test invalid configurations
    try {
        await runDKG(1, 5)
        t.fail('should reject threshold < 2')
    } catch (_e) {
        t.ok(true, 'should reject threshold < 2')
    }

    try {
        await runDKG(6, 5)
        t.fail('should reject threshold > n')
    } catch (_e) {
        t.ok(true, 'should reject threshold > n')
    }
})

test('FROST threshold signing (3-of-5)', async t => {
    // Run DKG first
    const { participants, groupPublicKey } = await runDKG(3, 5)

    const message = 'Test message for FROST signing'

    // You create a `BigInt` by appending the letter n to the end
    // of an integer.
    const signerIds = [1n, 2n, 3n]  // Select 3 participants to sign
    const signers:FrostSigner[] = []

    for (const id of signerIds) {
        const participant = participants.find(p => p.id === id)
        if (!participant) {
            t.fail(`Could not find participant ${id}`)
            return
        }

        // Build verification shares map
        const verificationShares = new Map()
        for (const p of participants) {
            if (p.verificationShare) {
                verificationShares.set(p.id, p.verificationShare)
            }
        }

        const signer = new FrostSigner(
            participant.id,
            participant.secretShare!,
            participant.verificationShare!,
            participant.publicKey!,
            verificationShares
        )
        signers.push(signer)
    }

    // Round 1: Generate commitments
    const commitments = signers.map(s => s.generateCommitment())
    t.equal(commitments.length, 3, 'should have 3 commitments')

    // Round 2: Generate signature shares
    const signatureShares = signers.map(s =>
        s.generateSignatureShare(message, commitments, signerIds)
    )
    t.equal(signatureShares.length, 3, 'should have 3 signature shares')

    // Aggregate signature
    const signature = aggregateSignatures(
        message,
        commitments,
        signatureShares,
    )

    // Verify signature
    const valid = verifySignature(message, signature, groupPublicKey)
    t.ok(valid, 'signature should be valid')

    // Test with wrong message
    const invalidMessage = verifySignature(
        'Wrong message',
        signature,
        groupPublicKey
    )
    t.ok(!invalidMessage, 'signature should be invalid for wrong message')
})

test('FROST signing with different participant sets', async t => {
    // Run DKG
    const { participants, groupPublicKey } = await runDKG(3, 5)

    const message = 'Another test message'

    // Test with participants 2, 4, 5
    const signerIds = [2n, 4n, 5n]
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of participants) {
            if (p.verificationShare) {
                verificationShares.set(p.id, p.verificationShare)
            }
        }

        signers.push(new FrostSigner(
            participant.id,
            participant.secretShare!,
            participant.verificationShare!,
            participant.publicKey!,
            verificationShares
        ))
    }

    const commitments = signers.map(s => s.generateCommitment())
    const signatureShares = signers.map(s =>
        s.generateSignatureShare(message, commitments, signerIds)
    )
    const signature = aggregateSignatures(
        message,
        commitments,
        signatureShares,
    )

    const valid = verifySignature(message, signature, groupPublicKey)
    t.ok(valid, 'signature from different participant set should be valid')
})

test('FROST signing with minimum threshold (2-of-3)', async t => {
    const { participants, groupPublicKey } = await runDKG(2, 3)

    const message = 'Minimal threshold test'
    const signerIds = [1n, 3n]
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of participants) {
            if (p.verificationShare) {
                verificationShares.set(p.id, p.verificationShare)
            }
        }

        signers.push(new FrostSigner(
            participant.id,
            participant.secretShare!,
            participant.verificationShare!,
            participant.publicKey!,
            verificationShares
        ))
    }

    const commitments = signers.map(s => s.generateCommitment())
    const signatureShares = signers.map(s =>
        s.generateSignatureShare(message, commitments, signerIds)
    )
    const signature = aggregateSignatures(
        message,
        commitments,
        signatureShares,
    )

    const valid = verifySignature(message, signature, groupPublicKey)
    t.ok(valid, '2-of-3 threshold signature should be valid')
})

test('DKG with arbitrary participant IDs', async t => {
    // Use random, non-consecutive IDs
    const participantIds = [42n, 1337n, 9999n, 100n, 777n]
    const threshold = 3
    const totalParticipants = 5

    // Initialize participants with arbitrary IDs
    const participants:FrostParticipant[] = []
    const publicKeys = new Map<bigint, ArrayBuffer>()

    for (const id of participantIds) {
        const participant = await FrostParticipant.init(threshold, totalParticipants, id)
        const pubKey = await participant.getPublicKey()
        publicKeys.set(participant.id, pubKey)
        participants.push(participant)
    }

    // Distribute public keys
    for (const p of participants) {
        for (const [id, pubKey] of publicKeys) {
            if (id !== p.id) {
                await p.registerPeerKey(id, pubKey)
            }
        }
    }

    // Round 1: Generate commitments
    const commitments = new Map<bigint, { participantId:bigint, commitments:EdwardsPoint[], proof:any }>()
    for (const p of participants) {
        const data = await p.round1_generateCommitments()
        commitments.set(p.id, data)

        // Verify proof of knowledge
        const valid = p.verifySchnorrProof(p.id, data.proof)
        t.ok(valid, `proof from participant ${p.id} should be valid`)
    }

    // Round 2: Generate and distribute shares
    const allShares = new Map<bigint, Map<bigint, Uint8Array>>()
    for (const p of participants) {
        const shares = await p.round2_generateShares()
        allShares.set(p.id, shares)
    }

    // Distribute shares
    for (const sender of participants) {
        const shares = allShares.get(sender.id)!
        const senderCommitments = commitments.get(sender.id)!.commitments

        for (const receiver of participants) {
            if (sender.id !== receiver.id) {
                const encryptedShare = shares.get(receiver.id)!
                await receiver.receiveShare(sender.id, encryptedShare, senderCommitments)
            }
        }
    }

    // Round 3: Verify shares and compute final keys
    for (const p of participants) {
        for (const [fromId, _] of p.receivedShares) {
            const valid = p.verifyShare(fromId)
            t.ok(valid, `share from ${fromId} to ${p.id} should verify`)
        }
    }

    // Compute secret shares
    for (const p of participants) {
        p.computeSecretShare()
        p.computeVerificationShare()
    }

    // Compute group public key
    const allCommitmentArrays = Array.from(commitments.values()).map(d => d.commitments)
    const groupPublicKey = participants[0].computeGroupPublicKey(allCommitmentArrays)

    // All participants compute the same group key
    for (const p of participants) {
        p.computeGroupPublicKey(allCommitmentArrays)
    }

    // Verify all participants have the same group public key
    const firstPubKey = participants[0].publicKey!.toHex()
    for (const p of participants) {
        t.equal(
            p.publicKey!.toHex(),
            firstPubKey,
            `participant ${p.id} should have same group public key`
        )
    }

    // Test signing with arbitrary IDs
    const message = 'Test with arbitrary IDs'
    const signerIds = [42n, 777n, 9999n] // Select 3 participants
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of participants) {
            if (p.verificationShare) {
                verificationShares.set(p.id, p.verificationShare)
            }
        }

        signers.push(new FrostSigner(
            participant.id,
            participant.secretShare!,
            participant.verificationShare!,
            participant.publicKey!,
            verificationShares
        ))
    }

    const signingCommitments = signers.map(s => s.generateCommitment())
    const signatureShares = signers.map(s =>
        s.generateSignatureShare(message, signingCommitments, signerIds)
    )
    const signature = aggregateSignatures(
        message,
        signingCommitments,
        signatureShares,
    )

    const valid = verifySignature(message, signature, groupPublicKey)
    t.ok(valid, 'signature with arbitrary IDs should be valid')
})

test('DKG with auto-generated participant IDs', async t => {
    const threshold = 3
    const totalParticipants = 5

    const participants:FrostParticipant[] = []
    const publicKeys = new Map<bigint, ArrayBuffer>()

    for (let i = 0; i < totalParticipants; i++) {
        const participant = await FrostParticipant.init(
            threshold,
            totalParticipants
        )
        const pubKey = await participant.getPublicKey()
        publicKeys.set(participant.id, pubKey)
        participants.push(participant)
        t.ok(participant.id > 0n,
            `participant ${i} should have auto-generated ID`)
    }

    // Verify all IDs are unique
    const idSet = new Set(participants.map(p => p.id))
    t.equal(idSet.size, totalParticipants,
        'all auto-generated IDs should be unique')

    // Distribute public keys
    for (const p of participants) {
        for (const [id, pubKey] of publicKeys) {
            if (id !== p.id) {
                await p.registerPeerKey(id, pubKey)
            }
        }
    }

    // Run through DKG rounds
    const commitments = new Map<bigint, Commitment>()
    for (const p of participants) {
        const data = await p.round1_generateCommitments()
        commitments.set(p.id, data)

        const valid = p.verifySchnorrProof(p.id, data.proof)
        t.ok(valid,
            `proof from auto-generated participant ID ${p.id} should be valid`)
    }

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

    for (const p of participants) {
        for (const [fromId, _] of p.receivedShares) {
            const valid = p.verifyShare(fromId)
            t.ok(valid, `share from ${fromId} to ${p.id} should verify`)
        }
    }

    for (const p of participants) {
        p.computeSecretShare()
        p.computeVerificationShare()
    }

    const allCommitmentArrays = Array.from(commitments.values()).map(d => {
        return d.commitments
    })
    const groupPublicKey = participants[0]
        .computeGroupPublicKey(allCommitmentArrays)

    for (const p of participants) {
        p.computeGroupPublicKey(allCommitmentArrays)
    }

    // Verify all participants have the same group public key
    const firstPubKey = participants[0].publicKey!.toHex()
    for (const p of participants) {
        t.equal(
            p.publicKey!.toHex(),
            firstPubKey,
            `participant with auto-ID ${p.id} should have same group public key`
        )
    }

    // Test signing with auto-generated IDs
    const message = 'Test with auto-generated IDs'
    const signerIds = [
        participants[0].id,
        participants[2].id,
        participants[4].id
    ]  // Select 3 participants
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of participants) {
            if (p.verificationShare) {
                verificationShares.set(p.id, p.verificationShare)
            }
        }

        signers.push(new FrostSigner(
            participant.id,
            participant.secretShare!,
            participant.verificationShare!,
            participant.publicKey!,
            verificationShares
        ))
    }

    const signingCommitments = signers.map(s => s.generateCommitment())
    const signatureShares = signers.map(s =>
        s.generateSignatureShare(message, signingCommitments, signerIds)
    )
    const signature = aggregateSignatures(
        message,
        signingCommitments,
        signatureShares,
    )

    const valid = verifySignature(message, signature, groupPublicKey)
    t.ok(valid, 'signature with auto-generated IDs should be valid')
})

// Helper function to run DKG for testing
async function runDKG (threshold:number, totalParticipants:number) {
    if (threshold < 2) {
        throw new Error('Threshold must be at least 2')
    }
    if (threshold > totalParticipants) {
        throw new Error('Threshold cannot exceed total participants')
    }

    // Initialize participants
    const participants:FrostParticipant[] = []
    const publicKeys = new Map<bigint, ArrayBuffer>()

    for (let i = 1; i <= totalParticipants; i++) {
        const participant = await FrostParticipant.init(
            threshold,
            totalParticipants,
            i
        )
        const pubKey = await participant.getPublicKey()
        publicKeys.set(participant.id, pubKey)
        participants.push(participant)
    }

    // Distribute public keys
    for (const p of participants) {
        for (const [id, pubKey] of publicKeys) {
            if (id !== p.id) {
                await p.registerPeerKey(Number(id), pubKey)
            }
        }
    }

    // Round 1: Generate commitments
    const commitments = new Map<bigint, Commitment>()
    for (const p of participants) {
        const data = await p.round1_generateCommitments()
        commitments.set(p.id, data)

        // Verify proof of knowledge
        const valid = p.verifySchnorrProof(p.id, data.proof)
        if (!valid) {
            throw new Error(`Invalid proof of knowledge from participant ${p.id}`)
        }
    }

    // Round 2: Generate and distribute shares
    const allShares = new Map<bigint, Map<bigint, Uint8Array>>()
    for (const p of participants) {
        const shares = await p.round2_generateShares()
        allShares.set(p.id, shares)
    }

    // Distribute shares
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

    // Round 3: Verify shares and compute final keys
    for (const p of participants) {
        for (const [fromId, _] of p.receivedShares) {
            const valid = p.verifyShare(fromId)
            if (!valid) {
                throw new Error(`Invalid share from ${fromId} to ${p.id}`)
            }
        }
    }

    // Compute secret shares
    for (const p of participants) {
        p.computeSecretShare()
        p.computeVerificationShare()
    }

    // Compute group public key
    const allCommitmentArrays = Array.from(commitments.values()).map(d => {
        return d.commitments
    })
    const groupPublicKey = participants[0]
        .computeGroupPublicKey(allCommitmentArrays)

    // All participants compute the same group key
    for (const p of participants) {
        p.computeGroupPublicKey(allCommitmentArrays)
    }

    return { participants, groupPublicKey, threshold, n: totalParticipants }
}
