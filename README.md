# FROST DKG
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/frost-dkg/nodejs.yml?style=flat-square)](https://github.com/substrate-system/frost-dkg/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/frost-dkg?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/frost-dkg)](https://packagephobia.com/result?p=@substrate-system/frost-dkg)
[![gzip size](https://img.shields.io/bundlephobia/minzip/@substrate-system/frost-dkg?style=flat-square)](https://bundlephobia.com/@substrate-system/frost-dkg)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


FROST DKG enables multiple participants to generate a shared
secret key without any single party ever knowing the complete key. The protocol
produces a threshold signature scheme where any `t` out of `n` participants can
sign messages, but fewer than `t` cannot.

**_Featuring_**

- **Threshold Cryptography**: Supports t-of-n threshold schemes
  (e.g., 3-of-5, 2-of-3)
- **Secure Share Distribution**: Encrypted share exchange using X25519 key
  agreement and AES-GCM
- **Zero-Knowledge Proofs**: Schnorr proofs of knowledge for
  commitment verification
- **Ed25519 Curve**: Built on the secure Ed25519 elliptic curve
- **Full TypeScript**: Type-safe implementation with comprehensive
  type definitions


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Installation](#installation)
- [Usage](#usage)
  * [Basic Example](#basic-example)
  * [Advanced Usage: Manual Round Execution](#advanced-usage-manual-round-execution)
- [API Reference](#api-reference)
  * [`FrostDKG`](#frostdkg)
  * [`FrostParticipant`](#frostparticipant)
  * [Utility Functions](#utility-functions)
- [Protocol Overview](#protocol-overview)
  * [Round 1: Commitment Phase](#round-1-commitment-phase)
  * [Round 2: Share Distribution](#round-2-share-distribution)
  * [Round 3: Verification and Key Computation](#round-3-verification-and-key-computation)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Browser Compatibility](#browser-compatibility)
- [See also](#see-also)

<!-- tocstop -->

</details>


## Install

```sh
npm i -S @substrate-system/frost-dkg
```

## Use

### Example

```ts
import { FrostDKG } from '@substrate-system/frost-dkg'

// Create a 3-of-5 threshold scheme
const dkg = new FrostDKG(3, 5)

// Run the complete DKG protocol
const result = await dkg.run()

console.log('Threshold:', result.threshold)
console.log('Total participants:', result.n)
console.log('Group public key:', result.groupPublicKey)

// Each participant now has a secret share
result.participants.forEach(p => {
  console.log(`Participant ${p.id}:`)
  console.log('  Secret share:', p.secretShare)
  console.log('  Verification share:', p.verificationShare)
})
```

### Advanced Example: Manual Round Execution

For distributed systems where participants are on different machines, you can
execute each round manually:

```ts
import { FrostParticipant } from '@substrate-system/frost-dkg'

// Each participant initializes independently
const participant = new FrostParticipant(1, 3, 5)  // id=1, threshold=3, total=5
const myPublicKey = await participant.initialize()

// Exchange public keys with other participants
// (implement your own network communication here)
await participant.registerPeerKey(2, otherParticipantPublicKey)

// Round 1: Generate commitments
const { commitments, proof } = await participant.round1_generateCommitments()
// Broadcast commitments to all participants

// Round 2: Generate shares
const encryptedShares = await participant.round2_generateShares()
// Send encrypted shares to respective participants

// Round 2: Receive shares from others
await participant.receiveShare(senderId, encryptedShare, senderCommitments)

// Round 3: Verify and compute final shares
const isValid = participant.verifyShare(senderId)
const secretShare = participant.computeSecretShare()
const verificationShare = participant.computeVerificationShare()
```

## API


### `FrostDKG`

Main class for running the complete DKG protocol.

#### Constructor

```ts
new FrostDKG(threshold:number, totalParticipants:number)
```

- `threshold`: Minimum number of participants needed to sign (must be ≥ 2)
- `totalParticipants`: Total number of participants (must be ≥ threshold)

#### Methods

##### `run`

```ts
async run ():Promise<{
    threshold:number;
    n:number;
    participants:ParticipantState[];
    groupPublicKey:string;
}>
```

Executes the complete DKG protocol and returns the result.

##### `initialize`

```ts
async initialize ():Promise<void>
```

Initializes all participants with X25519 key pairs.

##### `executeRound1`

```ts
async executeRound1 ():Promise<void>
```

Round 1: Generates polynomial commitments and Schnorr proofs of knowledge.

##### `executeRound2`

```ts
async executeRound2 ():Promise<void>
```

Round 2: Generates and exchanges encrypted shares between participants.

##### `executeRound3`

```ts
async executeRound3 ():Promise<void>
```

Round 3: Verifies received shares and computes final secret and
verification shares.

--------------------------------

### `FrostParticipant`

Individual participant in the DKG protocol.

#### Constructor

```ts
new FrostParticipant(id:number, threshold:number, totalParticipants:number)
```

#### Methods

##### `initialize`

```ts
async initialize ():Promise<ArrayBuffer>
```

Initializes the participant and returns their X25519 public key.

##### `registerPeerKey`

```ts
async registerPeerKey (
    peerId:number,
    publicKeyBytes:ArrayBuffer
):Promise<void>
```

Register another participant's public key for encrypted communication.

##### `round1_generateCommitments`

```ts
async round1_generateCommitments ():Promise<{
    participantId: bigint;
    commitments: Point[];
    proof: { R: Point; s: bigint; A: Point };
}>
```

Generate polynomial coefficients and commitments.

##### `verifySchnorrProof`

```ts
verifySchnorrProof (participantId:bigint, proof):boolean
```

Verifies a Schnorr proof of knowledge from another participant.

##### `round2_generateShares`

```ts
async round2_generateShares ():Promise<Map<bigint, Uint8Array>>
```

Generates encrypted shares for all other participants.

##### `receiveShare`

```ts
async receiveShare (
    fromId:number,
    encryptedShare:Uint8Array,
    commitments:Point[]
):Promise<void>
```

Receives and decrypts a share from another participant.

##### `verifyShare`

```ts
verifyShare (fromId:number):boolean
```

Verifies a received share using the sender's commitments.

##### `computeSecretShare`

```ts
computeSecretShare ():bigint
```

Computes the final secret share.

##### `computeVerificationShare`

```ts
computeVerificationShare ():Point
```

Computes the verification share (public key share).

##### `computeGroupPublicKey`

```ts
computeGroupPublicKey (allCommitments):Point
```

Computes the group public key from all participants' commitments.

##### `exportState`

```ts
exportState ():ParticipantState
```

Exports the participant's state for inspection.

### Utility Functions

#### `randomScalar`

```ts
randomScalar ():bigint
```

Generates a random scalar in the curve order.

#### `scalarToBytes`

```ts
scalarToBytes (scalar:bigint):Uint8Array
```

Converts a scalar to a 32-byte little-endian representation.

#### `deriveSharedSecret`

```ts
async deriveSharedSecret (
    privateKey:CryptoKey,
    publicKey:CryptoKey
):Promise<Uint8Array>
```

Derives a shared secret using X25519 key agreement.

#### `encryptShare`

```ts
async encryptShare (
    sharedSecret:Uint8Array,
    plaintext:Uint8Array
):Promise<Uint8Array>
```

Encrypts data using AES-GCM with a derived key.

#### `decryptShare`

```ts
async decryptShare (
    sharedSecret:Uint8Array,
    encrypted:Uint8Array
):Promise<Uint8Array>
```

Decrypts data encrypted with `encryptShare`.


-------


## How Does It Work?

FROST DKG consists of three rounds:

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


-------


## Security Considerations

- **Secure Channels**: Shares are encrypted using X25519 key agreement + AES-GCM
- **Commitment Verification**: Schnorr proofs ensure participants know
  their secrets
- **Share Verification**: Pedersen commitments allow verification without
  revealing shares
- **Threshold Security**: Any `t` participants can reconstruct the key,
  but `t-1` cannot

## Test

```sh
npm test
```

## Browser Compatibility

This library uses the Web Crypto API and works in all modern browsers:

- Chrome/Edge 60+
- Firefox 53+
- Safari 11+

## See also

- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)
- [Penumbra FROST DKG Documentation](https://protocol.penumbra.zone/main/crypto/flow-encryption/dkg.html#frost)
- [@noble/curves](https://github.com/paulmillr/noble-curves) - Cryptographic
  curves implementation
- [Pedersen's Verifiable Secret Sharing](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)

This implementation follows the
[FROST DKG protocol](https://protocol.penumbra.zone/main/crypto/flow-encryption/dkg.html#frost).
