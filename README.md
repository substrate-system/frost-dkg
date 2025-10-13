# FROST DKG
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/frost-dkg/nodejs.yml?style=flat-square)](https://github.com/substrate-system/frost-dkg/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/frost-dkg?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/frost-dkg)](https://packagephobia.com/result?p=@substrate-system/frost-dkg)
[![gzip size](https://img.shields.io/bundlephobia/minzip/@substrate-system/frost-dkg?style=flat-square)](https://bundlephobia.com/@substrate-system/frost-dkg)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Multiple participants generate a shared secret key. No single party
ever knows the complete key. The protocol produces a threshold signature
scheme where any `t` out of `n` participants can sign messages, but fewer
than `t` cannot.

**_Featuring_**

- **Threshold Cryptography**: Supports t-of-n threshold schemes
  (e.g., 3-of-5, 2-of-3)
- **Secure Share Distribution**: Encrypted share exchange using X25519 key
  agreement and AES-GCM
- **Zero-Knowledge Proofs**: Schnorr proofs of knowledge for
  commitment verification
- **Ed25519 Curve**: Built on Ed25519 elliptic curve


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Use](#use)
  * [Distributed Key Generation](#distributed-key-generation)
  * [Verify Schnorr Proofs](#verify-schnorr-proofs)
  * [Receive Shares, Create a Public Key](#receive-shares-create-a-public-key)
    + [Secrets and Verification](#secrets-and-verification)
  * [Sign Something](#sign-something)
- [API](#api)
  * [`FrostDKG`](#frostdkg)
    + [Constructor](#constructor)
    + [Methods](#methods)
  * [`FrostParticipant`](#frostparticipant)
    + [Static Methods](#static-methods)
    + [Methods](#methods-1)
  * [Utility Functions](#utility-functions)
    + [`randomScalar`](#randomscalar)
    + [`scalarToBytes`](#scalartobytes)
    + [`deriveSharedSecret`](#derivesharedsecret)
    + [`encryptShare`](#encryptshare)
    + [`decryptShare`](#decryptshare)
- [How Does It Work?](#how-does-it-work)
  * [Round 1: Commitment Phase](#round-1-commitment-phase)
  * [Round 2: Share Distribution](#round-2-share-distribution)
  * [Round 3: Verification and Key Computation](#round-3-verification-and-key-computation)
  * [When signing](#when-signing)
- [Security Considerations](#security-considerations)
- [Test](#test)
- [Browser Compatibility](#browser-compatibility)
- [See also](#see-also)

<!-- tocstop -->

</details>


## Install

```sh
npm i -S @substrate-system/frost-dkg
```

## Use

### Distributed Key Generation

In a real life, each participant runs independently on different machines.
(You would implement a network layer to pass messages between them.)

The peer IDs should be consecutive numbers from 1 - `<total number of peers>`.
The peer IDs must be coordinated amongst peers to avoid collisions.

>
> [!IMPORTANT]
> Before starting, participants must coordinate to ensure each has a unique ID
> (1 through n) to avoid collisions. The threshold and total participants are
> typically already agreed upon (e.g., "we're doing a 3-of-5 scheme"), but if
> they mismatch, the protocol will fail during verification.
>

```ts
import { FrostParticipant } from '@substrate-system/frost-dkg/participant'

// Initialize participant 1 of a 3-of-5 scheme
// My ID is 1, threshold is 3, total participants is 5
const participant = await FrostParticipant.init(1, 3, 5)  // this is me

// this public key is used to decrypt the shared key shards
const myPublicKey = await participant.getPublicKey()

// >> Send myPublicKey to machines 2, 3, 4, 5 via network <<

// ... Receive publicKey2, publicKey3, publicKey4, publicKey5 from network ...

// call `registerPeerKey` for each peer
await participant.registerPeerKey(2, publicKey2)
await participant.registerPeerKey(3, publicKey3)
await participant.registerPeerKey(4, publicKey4)
await participant.registerPeerKey(5, publicKey5)

// Round 1: Generate commitments and proof.
// Broadcast these in the next step.
const { commitments, proof } = await participant.round1_generateCommitments()
```

### Verify Schnorr Proofs

Before participants exchange shares, each should verify that others actually
know their secret polynomial coefficients. The Schnorr proof verification
confirms that each participant has honestly generated their commitments and
knows the secret they've committed to, without revealing that secret.

This is a zero-knowledge proof &mdash; if verification passes, you can be
confident the participant isn't cheating, but you learn nothing about their
actual secret value. If any proof fails, the protocol should be aborted, as it
indicates a malicious or misconfigured participant.

```ts
// >> Broadcast my commitments & proof to all machines <<

// ... Receive commitments & proofs from machines 2, 3, 4, 5 ...

// Each machine sends you their { commitments, proof } from Round 1
// You'll need the commitments later in Round 3.
const { commitments: commitments2, proof: proof2 } = /* from machine 2 */
const { commitments: commitments3, proof: proof3 } = /* from machine 3 */
const { commitments: commitments4, proof: proof4 } = /* from machine 4 */
const { commitments: commitments5, proof: proof5 } = /* from machine 5 */

// Verify everyone's proof
// the `n` after each number (`1n`, `2n`) means it is a BigInt
participant.verifySchnorrProof(2n, proof2)  // from machine 2
participant.verifySchnorrProof(3n, proof3)  // from machine 3
participant.verifySchnorrProof(4n, proof4)  // from machine 4
participant.verifySchnorrProof(5n, proof5)  // from machine 5

// __Round 2: Generate encrypted shares__
const encryptedShares = await participant.round2_generateShares()


// >> Send encryptedShare.get(2) to machine 2 <<
// >> Send encryptedShare.get(3) to machine 3 <<
// >> Send encryptedShare.get(4) to machine 4 <<
// >> Send encryptedShare.get(5) to machine 5 <<
```

### Receive Shares, Create a Public Key

After Round 2, each participant has received encrypted shares from all other
participants. The `receiveShare` method decrypts these shares using the X25519
shared secret established during step 1.

The `verifyShare` method then uses Pedersen commitments (the polynomial
commitments from Round 1) to cryptographically verify that each decrypted share
is correct.

This verification checks that the share matches the sender's
commitments without revealing the share's value. This step
detects malicious or faulty participants before computing the final secret
share. If any verification fails, the protocol should be aborted.

```ts
// ... Receive the encrypted shares from machines 2, 3, 4, 5 ...

await participant.receiveShare(2, shareFromMachine2, commitments2)
await participant.receiveShare(3, shareFromMachine3, commitments3)
await participant.receiveShare(4, shareFromMachine4, commitments4)
await participant.receiveShare(5, shareFromMachine5, commitments5)

// Round 3: Verify shares
participant.verifyShare(2)  // true
participant.verifyShare(3)  // true
participant.verifyShare(4)  // true
participant.verifyShare(5)  // true

// Compute final key material
const secret = participant.computeSecretShare()  // secret value
const myVerification = participant.computeVerificationShare()

// This computes and sets the public key as `participant.publicKey`.
const groupPublicKey = participant.computeGroupPublicKey([
  commitments1,  // my own
  commitments2,
  commitments3,
  commitments4,
  commitments5
])

// ... share the `myVerification` with the other participants ...
// That's how they verify you.

console.log('My secret share:', secret.toString())
console.log('My verification share:', myVerification.toHex())
console.log('Group public key:', groupPublicKey.toHex())
```

#### Secrets and Verification

In the last example, we generated a few things.
**What to do with these values**:

`secret`: Your portion of the distributed private key

- Store securely
- NEVER share this
- Needed whenever you want to participate in signing

`myVerification`: Your public key share (proves you know your secret)

- Share with all other participants (public info)
- Everyone needs everyone else's verification shares for signing

`groupPublicKey`: The shared public key for the entire group

- Share publicly - anyone can use this to verify signatures
- All participants should compute the same groupPublicKey


### Sign Something

Now we have used the participants to generate a public key. Let's use 3
of the 5 total participants to sign a message.

```ts
import {
    FrostSigner,
    aggregateSignatures,
    verifySignature
} from '@substrate-system/frost-dkg'

// Each signing participant needs their secret and verification share,
// plus all participants' verification shares (public info)
const verificationShares = new Map([
  [1n, verificationShare1],
  [2n, verificationShare2],
  [3n, verificationShare3],
  [4n, verificationShare4],
  [5n, verificationShare5]
])

// participants 1, 3, and 5 are signing. Each signer is a different machine.
// Each creates a FrostSigner with their own secret share
const signer1 = new FrostSigner(
  1n,
  secret,
  verificationShare1,
  groupPublicKey,
  verificationShares
)

// machine 3

const signer3 = new FrostSigner(
    3n,
    secret3,
    verificationShare3,
    groupPublicKey,
    verificationShares
)

// machine 5

const signer5 = new FrostSigner(
    5n,
    secret5,
    verificationShare5,
    groupPublicKey,
    verificationShares
)

const message = 'Hello, FROST!'
const signerIds = [1n, 3n, 5n]

// Round 1: Each signer generates a commitment
const commitment1 = signer1.generateCommitment()
const commitment3 = signer3.generateCommitment()
const commitment5 = signer5.generateCommitment()
const commitments = [commitment1, commitment3, commitment5]

// Round 2: Each signer generates their signature share
const share1 = signer1.generateSignatureShare(message, commitments, signerIds)
const share3 = signer3.generateSignatureShare(message, commitments, signerIds)
const share5 = signer5.generateSignatureShare(message, commitments, signerIds)

// these signature shares can be transferred to any machine to verify
const shares = [share1, share3, share5]

// Anyone can aggregate the shares into a final signature
const signature = aggregateSignatures(message, commitments, shares)

// Anyone can verify the signature with just the group public key
const isValid = verifySignature(message, signature, groupPublicKey)
console.log('Valid:', isValid)  // true
```

**Notes**

- Each signer only uses their own secret share
- No single machine ever sees the full private key
- The private key doesn't exist anywhere - it's mathematically distributed
- Any 3 machines can later collaborate to sign messages
- Shares are encrypted during transmission (X25519 + AES-GCM)
- All machines compute the same group public key
- Lagrange interpolation happens during signing
- The full secret key is never reconstructed


## API

### `FrostDKG`

Main class for running the DKG protocol.

#### Constructor

```ts
new FrostDKG(threshold:number, totalParticipants:number)
```

- `threshold`: Minimum number of participants needed to sign (must be ≥ 2)
- `totalParticipants`: Total number of participants (must be ≥ threshold)

#### Methods

##### `run`

```ts
class FrostDKG {
    async run ():Promise<{
        threshold:number;
        n:number;
        participants:ParticipantState[];
        groupPublicKey:string;
    }>
}
```

Executes the complete DKG protocol and returns the result.

##### `initialize`

```ts
class FrostDKG {
    async initialize ():Promise<void>
}
```

Initializes all participants with X25519 key pairs.

##### `executeRound1`

```ts
class FrostDKG {
    async executeRound1 ():Promise<void>
}
```

Round 1: Generates polynomial commitments and Schnorr proofs of knowledge.

##### `executeRound2`

```ts
class FrostDKG {
    async executeRound2 ():Promise<void>
}
```

Round 2: Generates and exchanges encrypted shares between participants.

##### `executeRound3`

```ts
class FrostDKG {
    async executeRound3 ():Promise<void>
}
```

Round 3: Verifies received shares and computes final secret and
verification shares.



--------------------------------



### `FrostParticipant`

Individual participant in the DKG protocol.

#### Static Methods

##### `init`

```ts
class FrostParticipant {
    static async init (
        id:number,
        threshold:number,
        totalParticipants:number
    ):Promise<FrostParticipant>
}
```

Creates and initializes a new FrostParticipant with an X25519 keypair.

- `id`: Unique identifier for this participant (1-indexed)
- `threshold`: Minimum number of participants needed for signing
- `totalParticipants`: Total number of participants in the DKG

#### Methods

##### `getPublicKey`

```ts
class FrostParticipant {
    async getPublicKey ():Promise<ArrayBuffer>
}
```

Returns the participant's X25519 public key for encrypted communication.

##### `registerPeerKey`

```ts
class FrostParticipant {
    async registerPeerKey (
        peerId:number,
        publicKeyBytes:ArrayBuffer
    ):Promise<void>
}
```

Register another participant's public key for encrypted communication.

##### `round1_generateCommitments`

```ts
class FrostParticipant {
    async round1_generateCommitments ():Promise<{
        participantId: bigint;
        commitments: Point[];
        proof: { R: Point; s: bigint; A: Point };
    }>
}
```

Generate polynomial coefficients and commitments.

##### `verifySchnorrProof`

```ts
class FrostParticipant {
    verifySchnorrProof (participantId:bigint, proof):boolean
}
```

Verifies a Schnorr proof of knowledge from another participant.

##### `round2_generateShares`

```ts
class FrostParticipant {
    async round2_generateShares ():Promise<Map<bigint, Uint8Array>>
}
```

Generates encrypted shares for all other participants.

##### `receiveShare`

```ts
class FrostParticipant {
    async receiveShare (
        fromId:number,
        encryptedShare:Uint8Array,
        commitments:Point[]
    ):Promise<void>
}
```

Receives and decrypts a share from another participant.

##### `verifyShare`

```ts
class FrostParticipant {
    verifyShare (fromId:number):boolean
}
```

Verifies a received share using the sender's commitments.

##### `computeSecretShare`

```ts
class FrostParticipant {
    computeSecretShare ():bigint
}
```

Computes the final secret share.

##### `computeVerificationShare`

```ts
class FrostParticipant {
    computeVerificationShare ():Point
}
```

Computes the verification share (public key share).

##### `computeGroupPublicKey`

```ts
class FrostParticipant {
    computeGroupPublicKey (allCommitments):Point
}
```

Computes the group public key from all participants' commitments.

##### `exportState`

```ts
class FrostParticipant {
    exportState ():ParticipantState
}
```

Exports the participant's state for inspection.

### Utility Functions

#### `randomScalar`

```ts
class FrostParticipant {
    randomScalar ():bigint
}
```

Generates a random scalar in the curve order.

#### `scalarToBytes`

```ts
class FrostParticipant {
    scalarToBytes (scalar:bigint):Uint8Array
}
```

Converts a scalar to a 32-byte little-endian representation.

#### `deriveSharedSecret`

```ts
class FrostParticipant {
    async deriveSharedSecret (
        privateKey:CryptoKey,
        publicKey:CryptoKey
    ):Promise<Uint8Array>
}
```

Derives a shared secret using X25519 key agreement.

#### `encryptShare`

```ts
class FrostParticipant {
    async encryptShare (
        sharedSecret:Uint8Array,
        plaintext:Uint8Array
    ):Promise<Uint8Array>
}
```

Encrypts data using AES-GCM with a derived key.

#### `decryptShare`

```ts
class FrostParticipant {
    async decryptShare (
        sharedSecret:Uint8Array,
        encrypted:Uint8Array
    ):Promise<Uint8Array>
}
```

Decrypts data encrypted with `encryptShare`.


-------


## How Does It Work?

Participants collaborate to generate shards that are mathematically linked
together. **Nobody ever sees the full private key**.


### Round 1: Commitment Phase

1. Each participant generates a random polynomial of degree `t-1`
2. Computes commitments to polynomial coefficients
3. Generates a Schnorr proof of knowledge for the secret (constant term)
4. Broadcasts commitments and proof

### Round 2: Share Distribution

1. Each participant evaluates their polynomial at every participant's ID
2. Encrypts each share using X25519 + AES-GCM
3. Sends encrypted shares to respective participants

### Round 3: Verification and Key Computation

1. Each participant verifies received shares using sender's commitments
2. Computes final secret share as sum of all received shares
3. Computes verification share (public key share)
4. Computes group public key


### When signing

1. Select any t participants (say participants 1, 3, 5 in a 3-of-5 scheme)
2. Each selected participant:
    - Generates nonces and commitments
    - Computes a signature share using their secret share + Lagrange 
3. The signature shares are combined into a single signature

The Lagrange interpolation is key - it lets t participants reconstruct
what the full secret key would sign, without ever revealing the secret 
key.


-------


## Security Considerations

- **Encryption**: Shares are encrypted using X25519 key agreement + AES-GCM
- **Commitment Verification**: Schnorr proofs ensure other participants know
  their secrets
- **Share Verification**: Pedersen commitments allow verification without
  revealing shares
- **Threshold Security**: Any `t` participants can reconstruct the key,
  but `t-1` cannot


-----------

## Test

```sh
npm test
```

-----------


## Browser Compatibility

This library uses the Web Crypto API and works in all modern browsers:

- Chrome/Edge 60+
- Firefox 53+
- Safari 11+


-----------


## See also

- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)
- [Penumbra FROST DKG Documentation](https://protocol.penumbra.zone/main/crypto/flow-encryption/dkg.html#frost)
- [@noble/curves](https://github.com/paulmillr/noble-curves) - Cryptographic
  curves implementation
- [Pedersen's Verifiable Secret Sharing](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
