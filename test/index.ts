import { test } from '@substrate-system/tapzero'
import { bytesToNumberLE } from '@noble/curves/utils.js'
import {
    FrostDKG,
    FrostParticipant,
    ed25519,
    randomScalar,
    scalarToBytes,
    deriveSharedSecret,
    encryptShare,
    decryptShare
} from '../src/index.js'

test('proof of knowledge', async t => {
    const participant = new FrostParticipant(1, 3, 5)
    await participant.initialize()

    // Generate commitment
    const { proof } = await participant.round1_generateCommitments()

    // Verify proof
    const valid = participant.verifySchnorrProof(participant.id, proof)
    t.ok(valid, 'valid proof should be accepted')

    // Try with wrong proof
    const fakeProof = {
        R: ed25519.Point.BASE.multiply(randomScalar() as any),
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

    const p1PubKey = dkg.participants[0].peerPublicKeys.get(p2.id)
    const secret1 = await deriveSharedSecret(p1.x25519KeyPair.privateKey, p1PubKey)

    const encrypted = await encryptShare(secret1, testBytes)

    const p2PubKey = dkg.participants[1].peerPublicKeys.get(p1.id)
    const secret2 = await deriveSharedSecret(p2.x25519KeyPair.privateKey, p2PubKey)

    const decrypted = await decryptShare(secret2, encrypted)
    const recoveredShare = bytesToNumberLE(decrypted)

    t.equal(testShare, recoveredShare,
        'encryption/decryption should work correctly')
})

test('basic DKG (3-of-5)', async t => {
    const dkg = new FrostDKG(3, 5)
    await dkg.run()

    // Verify all participants have the same group public key
    const firstPubKey = dkg.participants[0].publicKey.toHex()
    for (const p of dkg.participants) {
        t.equal(
            p.publicKey.toHex(),
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
            computed.equals(p.verificationShare),
            `participant ${p.id} should have valid verification share`
        )
    }
})

test('minimal threshold (2-of-3)', async t => {
    const dkg = new FrostDKG(2, 3)
    await dkg.run()

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
    await dkg.run()

    // Verify that all participants computed the same group public key
    const firstPubKey = dkg.groupPublicKey
    for (const p of dkg.participants) {
        t.ok(p.publicKey.equals(firstPubKey),
            `participant ${p.id} computed correct group public key`)
    }
})

test('edge cases', async t => {
    // Test minimum configuration
    const dkg1 = new FrostDKG(2, 2)
    await dkg1.run()
    t.ok(true, '2-of-2 configuration should work')

    // Test larger configuration
    const dkg2 = new FrostDKG(5, 7)
    await dkg2.run()
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
