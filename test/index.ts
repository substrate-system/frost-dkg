import { test } from '@substrate-system/tapzero'
import { bytesToNumberLE } from '@noble/curves/utils.js'
import {
    randomScalar,
    scalarToBytes,
    deriveSharedSecret,
    encryptShare,
    decryptShare
} from '../src/util.js'
import { FrostParticipant } from '../src/participant.js'
import { FrostDKG } from '../src/test-helpers.js'
import { ed25519 } from '../src/index.js'
import {
    FrostSigner,
    aggregateSignatures,
    verifySignature
} from '../src/signing.js'

test('proof of knowledge', async t => {
    const participant = await FrostParticipant.init(1, 3, 5)

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
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()

    const p1 = dkg.participants[0]
    const p2 = dkg.participants[1]

    // Test encryption/decryption
    const testShare = randomScalar()
    const testBytes = scalarToBytes(testShare)

    const p1PubKey = dkg.participants[0].peerPublicKeys.get(p2.id)!
    const secret1 = await deriveSharedSecret(
        p1.x25519KeyPair!.privateKey,
        p1PubKey
    )

    const encrypted = await encryptShare(secret1, testBytes)

    const p2PubKey = dkg.participants[1].peerPublicKeys.get(p1.id)!
    const secret2 = await deriveSharedSecret(
        p2.x25519KeyPair!.privateKey,
        p2PubKey
    )

    const decrypted = await decryptShare(secret2, encrypted)
    const recoveredShare = bytesToNumberLE(decrypted)

    t.equal(testShare, recoveredShare,
        'encryption/decryption should work correctly')
})

test('basic DKG (3-of-5)', async t => {
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    // Verify all participants have the same group public key
    const firstPubKey = dkg.participants[0].publicKey!.toHex()
    for (const p of dkg.participants) {
        t.equal(
            p.publicKey!.toHex(),
            firstPubKey,
            `participant ${p.id} should have same group public key`
        )
    }

    // Verify verification shares are valid
    for (const p of dkg.participants) {
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
    const dkg = new FrostDKG(2, 3)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    t.equal(dkg.threshold, 2, 'should have correct threshold')
    t.equal(dkg.n, 3, 'should have correct number of participants')
    t.equal(dkg.participants.length, 3,
        'should have correct number of participant objects')
})

test('share verification', async t => {
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()

    // All shares should verify correctly
    for (const p of dkg.participants) {
        for (const [fromId, _] of p.receivedShares) {
            const valid = p.verifyShare(fromId)
            t.ok(valid, `share from ${fromId} to ${p.id} should verify`)
        }
    }
})

test('polynomial reconstruction', async t => {
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    // Verify that all participants computed the same group public key
    const firstPubKey = dkg.groupPublicKey!
    for (const p of dkg.participants) {
        t.ok(p.publicKey!.equals(firstPubKey),
            `participant ${p.id} computed correct group public key`)
    }
})

test('edge cases', async t => {
    // Test minimum configuration
    const dkg1 = new FrostDKG(2, 2)
    await dkg1.initialize()
    await dkg1.executeRound1()
    await dkg1.executeRound2()
    await dkg1.executeRound3()
    t.ok(true, '2-of-2 configuration should work')

    // Test larger configuration
    const dkg2 = new FrostDKG(5, 7)
    await dkg2.initialize()
    await dkg2.executeRound1()
    await dkg2.executeRound2()
    await dkg2.executeRound3()
    t.ok(true, '5-of-7 configuration should work')

    // Test invalid configurations
    try {
        // eslint-disable-next-line no-new
        new FrostDKG(1, 5)
        t.fail('should reject threshold < 2')
    } catch (_e) {
        t.ok(true, 'should reject threshold < 2')
    }

    try {
        // eslint-disable-next-line no-new
        new FrostDKG(6, 5)
        t.fail('should reject threshold > n')
    } catch (_e) {
        t.ok(true, 'should reject threshold > n')
    }
})

test('FROST threshold signing (3-of-5)', async t => {
    // Run DKG first
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    const message = 'Test message for FROST signing'

    // You create a `BigInt` by appending the letter n to the end
    // of an integer.
    const signerIds = [1n, 2n, 3n]  // Select 3 participants to sign
    const signers:FrostSigner[] = []

    for (const id of signerIds) {
        const participant = dkg.participants.find(p => p.id === id)
        if (!participant) {
            t.fail(`Could not find participant ${id}`)
            return
        }

        // Build verification shares map
        const verificationShares = new Map()
        for (const p of dkg.participants) {
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
    const valid = verifySignature(message, signature, dkg.groupPublicKey!)
    t.ok(valid, 'signature should be valid')

    // Test with wrong message
    const invalidMessage = verifySignature(
        'Wrong message',
        signature,
        dkg.groupPublicKey!
    )
    t.ok(!invalidMessage, 'signature should be invalid for wrong message')
})

test('FROST signing with different participant sets', async t => {
    // Run DKG
    const dkg = new FrostDKG(3, 5)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    const message = 'Another test message'

    // Test with participants 2, 4, 5
    const signerIds = [2n, 4n, 5n]
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = dkg.participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of dkg.participants) {
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

    const valid = verifySignature(message, signature, dkg.groupPublicKey!)
    t.ok(valid, 'signature from different participant set should be valid')
})

test('FROST signing with minimum threshold (2-of-3)', async t => {
    const dkg = new FrostDKG(2, 3)
    await dkg.initialize()
    await dkg.executeRound1()
    await dkg.executeRound2()
    await dkg.executeRound3()

    const message = 'Minimal threshold test'
    const signerIds = [1n, 3n]
    const signers: any[] = []

    for (const id of signerIds) {
        const participant = dkg.participants.find(p => p.id === id)!
        const verificationShares = new Map()
        for (const p of dkg.participants) {
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

    const valid = verifySignature(message, signature, dkg.groupPublicKey!)
    t.ok(valid, '2-of-3 threshold signature should be valid')
})
