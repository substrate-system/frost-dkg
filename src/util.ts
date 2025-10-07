import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { bytesToNumberLE } from '@noble/curves/utils.js'
import { randomBytes } from '@noble/hashes/utils.js'

export { bytesToNumberLE }

// Ed25519 curve order
const CURVE_ORDER = ed25519.Point.CURVE().n

/**
 * Modular arithmetic helper
 */
export function mod (n, m = CURVE_ORDER) {
    const result = n % m
    return result >= 0n ? result : result + m
}

export function modAdd (a, b) {
    return mod(a + b)
}

export function modMul (a, b) {
    return mod(a * b)
}

export function modPow (base, exp, modulus = CURVE_ORDER) {
    if (modulus === 1n) return 0n
    let result = 1n
    base = mod(base, modulus)
    let e = exp
    while (e > 0n) {
        if (e & 1n) result = mod(result * base, modulus)
        e = e >> 1n
        base = mod(base * base, modulus)
    }
    return result
}

/**
 * Generate random scalar in range [1, CURVE_ORDER)
 */
export function randomScalar () {
    const bytes = randomBytes(32)
    const num = bytesToNumberLE(bytes)
    return mod(num) || 1n // Ensure non-zero
}

/**
 * Convert bigint to 32-byte little-endian array
 */
export function scalarToBytes (scalar) {
    const bytes = new Uint8Array(32)
    let n = BigInt(scalar)
    for (let i = 0; i < 32; i++) {
        bytes[i] = Number(n & 0xFFn)
        n >>= 8n
    }
    return bytes
}

export async function deriveSharedSecret (privateKey, publicKey) {
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'X25519', public: publicKey },
        privateKey,
        256
    )
    return new Uint8Array(sharedSecret)
}

/**
 * Encrypt/Decrypt using AES-GCM with derived key
 */
export async function encryptShare (sharedSecret, plaintext) {
    const keyMaterial = await crypto.subtle.digest('SHA-256', sharedSecret)
    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintext
    )

    const result = new Uint8Array(iv.length + ciphertext.byteLength)
    result.set(iv)
    result.set(new Uint8Array(ciphertext), iv.length)
    return result
}

export async function decryptShare (
    sharedSecret:Uint8Array<ArrayBuffer>,
    encrypted:Uint8Array
) {
    const iv = encrypted.slice(0, 12)
    const ciphertext = encrypted.slice(12)

    const keyMaterial = await crypto.subtle.digest('SHA-256', sharedSecret)
    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )

    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    )

    return new Uint8Array(plaintext)
}

/**
 * Hash to scalar using SHA-512
 */
export function hashToScalar (...inputs) {
    const concat = new Uint8Array(inputs.reduce((acc, inp) => acc + inp.length, 0))
    let offset = 0
    for (const input of inputs) {
        concat.set(input, offset)
        offset += input.length
    }

    const hash = sha512(concat)
    const num = bytesToNumberLE(hash)
    return mod(num)
}

/**
 * Convert bigint to bytes for point serialization
 */
export function bigintToBytes (n) {
    return scalarToBytes(n)
}

/**
 * X25519 key generation and ECDH
 */
export async function generateX25519KeyPair () {
    return await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits']
    )
}
