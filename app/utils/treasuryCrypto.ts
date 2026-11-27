import { secp256k1 } from '@noble/curves/secp256k1'
import { bls12_381 } from '@noble/curves/bls12-381'
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { ripemd160 } from '@noble/hashes/ripemd160'

export const LEGACY_BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'
export const BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_KRISTA_LLMQ_TREASURY_V1_'
export const CORE_VERSION = 'v1.5.9.0'
export const PROTOCOL_VERSION = 70983
export const QUORUM_EQUIVOCATION_GUARD_SECS = 45

export const CHAIN_DEFAULTS: Readonly<
  Record<
    string,
    Readonly<{
      devFundAddr: string
      sporkPubKey: string
      treasuryGovernanceStartHeight: number
    }>
  >
> = Object.freeze({
  main: Object.freeze({
    devFundAddr: 'KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP',
    sporkPubKey: '024897ee03b6f8133aa5fc926c8f9fd83b1454a817fda9fc907de18866eba0030a',
    treasuryGovernanceStartHeight: 5000
  }),
  test: Object.freeze({
    devFundAddr: 'ktEooARF3HdV8w59LUc5jaHrS7GBL7974Uy',
    sporkPubKey: '03b4394f924c8bdbea7379fbcde9bf1b5a32d0f04631312b18c4ba3889a89b6a0d',
    treasuryGovernanceStartHeight: 200
  }),
  regtest: Object.freeze({
    devFundAddr: 'kt5KNitasi4bEHbQQCrpy6445nJD7uSVNux',
    sporkPubKey:
      '043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7',
    treasuryGovernanceStartHeight: 100
  })
})

/**
 * Dynamic LLMQ Quorum Scaling (UPGRADE_HARDENING_V1 in src/llmq.cpp:GetTargetQuorumSize)
 * with UPGRADE_HARDENING_V4 BFT Supermajority Thresholds (src/llmq.cpp:GetQuorumThreshold):
 *   < 25 active on-chain MNs   -> 5 members  (4/5 BFT supermajority)
 *   25..49 active on-chain MNs -> 9 members  (7/9 BFT supermajority)
 *   50..99 active on-chain MNs -> 11 members (8/11 BFT supermajority)
 *   >= 100 active on-chain MNs -> 15 members (11/15 BFT supermajority)
 */
export function getTargetQuorumSize(nActiveOnChainMNs: number): number {
  const count = Math.max(0, Math.floor(Number(nActiveOnChainMNs) || 0))
  if (count >= 100) return 15
  if (count >= 50) return 11
  if (count >= 25) return 9
  return 5
}

/**
 * V4 BFT supermajority threshold matching src/llmq.cpp:36-44 (UPGRADE_HARDENING_V4, Height 1):
 *   std::min<size_t>(quorumSize, std::max<size_t>(2, ((2 * quorumSize) / 3) + 1))
 */
export function getQuorumMajorityThreshold(quorumSize: number): number {
  const size = Math.max(0, Math.floor(Number(quorumSize) || 0))
  if (size <= 0) return 0
  return Math.min(size, Math.max(2, Math.floor((2 * size) / 3) + 1))
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_MAP: Record<string, number> = Object.create(null)
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET[i]!] = i
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const BECH32M_CONST = 0x2bc830a3
const BECH32M_LEGACY_CONST = 0x3fffffff

export function hexToBytes(hex: string): Uint8Array {
  const clean = String(hex || '').trim()
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error('Invalid hexadecimal string')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0')
  }
  return hex
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0
  for (const arr of arrays) {
    totalLength += arr.length
  }
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

export function doubleSha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(sha256(data))
}

export function hash160Bytes(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data))
}

export function calculateTxHash(rawTxHex: string): string {
  const rawBytes = hexToBytes(rawTxHex)
  const digest = doubleSha256Bytes(rawBytes)
  const reversed = new Uint8Array(digest).reverse()
  return bytesToHex(reversed)
}

export function decodeBase58(input: string): Uint8Array {
  const str = String(input || '').trim()
  if (!str) {
    throw new Error('Empty Base58 input')
  }
  const bytes: number[] = [0]
  for (let i = 0; i < str.length; i++) {
    const c = str[i]!
    const val = BASE58_MAP[c]
    if (val === undefined) {
      throw new Error('Invalid Base58 character')
    }
    let carry = val
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  for (let i = 0; str[i] === '1' && i < str.length - 1; i++) {
    bytes.push(0)
  }
  return new Uint8Array(bytes.reverse())
}

export function encodeBase58Check(payload: Uint8Array): string {
  const checksum = doubleSha256Bytes(payload).slice(0, 4)
  const data = concatBytes(payload, checksum)
  const digits: number[] = [0]
  for (let i = 0; i < data.length; i++) {
    let carry = data[i]!
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = ''
  for (let i = 0; data[i] === 0 && i < data.length - 1; i++) {
    out += '1'
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!]
  }
  return out
}

const VALID_WIF_PREFIXES = new Set([0x2b, 0x80, 0xef])

export function getRawPrivateKeyFromWIF(wifString: string): string {
  const decoded = decodeBase58(String(wifString || '').trim())
  let payload: Uint8Array | null = null
  let rawKey: Uint8Array | null = null
  try {
    // WIF is: [prefix (1B)] [privkey (32B)] [optional compression flag 0x01 (1B)] [checksum (4B)]
    if (decoded.length !== 37 && (decoded.length !== 38 || decoded[33] !== 0x01)) {
      throw new Error('Invalid WIF byte length or compression flag')
    }
    if (!VALID_WIF_PREFIXES.has(decoded[0]!)) {
      throw new Error(`Invalid WIF version prefix byte (0x${decoded[0]!.toString(16)})`)
    }
    payload = decoded.slice(0, decoded.length - 4)
    const checksum = decoded.subarray(decoded.length - 4)
    const expectedChecksum = doubleSha256Bytes(payload).slice(0, 4)
    for (let i = 0; i < 4; i++) {
      if (checksum[i] !== expectedChecksum[i]) {
        throw new Error('Invalid WIF Base58Check checksum')
      }
    }

    rawKey = decoded.slice(1, 33)
    if (rawKey.every((b) => b === 0) || !secp256k1.utils.isValidPrivateKey(rawKey)) {
      throw new Error('Invalid or out-of-range secp256k1 private key in WIF')
    }
    return bytesToHex(rawKey)
  } finally {
    decoded.fill(0)
    if (payload) payload.fill(0)
    if (rawKey) rawKey.fill(0)
  }
}

export function derivePubKeysFromWIF(wifString: string): {
  privKeyHex: string
  compressedPubKey: string
  uncompressedPubKey: string
} {
  const privKeyHex = getRawPrivateKeyFromWIF(wifString)
  const privBytes = hexToBytes(privKeyHex)
  try {
    return {
      privKeyHex,
      compressedPubKey: bytesToHex(secp256k1.getPublicKey(privBytes, true)).toLowerCase(),
      uncompressedPubKey: bytesToHex(secp256k1.getPublicKey(privBytes, false)).toLowerCase()
    }
  } finally {
    privBytes.fill(0)
  }
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of values) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i]!
    }
  }
  return chk
}

function verifyBech32mTaprootChecksum(
  address: string,
  expectedHrp: 'kt' | 'tk' | 'rt' | 'rk' | 'ktrt'
): boolean {
  const pos = address.lastIndexOf('1')
  if (pos !== expectedHrp.length || address.slice(0, pos) !== expectedHrp) return false
  const dataPart = address.slice(pos + 1)
  if (dataPart.length !== 59) return false
  const values: number[] = []
  for (let i = 0; i < expectedHrp.length; i++) {
    values.push(expectedHrp.charCodeAt(i) >>> 5)
  }
  values.push(0)
  for (let i = 0; i < expectedHrp.length; i++) {
    values.push(expectedHrp.charCodeAt(i) & 31)
  }
  for (let i = 0; i < dataPart.length; i++) {
    const idx = BECH32_CHARSET.indexOf(dataPart[i]!)
    if (idx === -1) return false
    values.push(idx)
  }
  if (values[expectedHrp.length * 2 + 1] !== 1) return false
  const polymod = bech32Polymod(values)
  return polymod === BECH32M_CONST || polymod === BECH32M_LEGACY_CONST
}

/**
 * Normalizes a KristaTech address: lowercases Bech32m Taproot addresses (kt1p..., tk1p..., rt1p..., rk1p..., ktrt1p...)
 * while preserving case-sensitive Base58Check addresses (KT... / kt...).
 */
export function normalizeTaprootAddress(address: string): string {
  const trimmed = String(address || '').trim()
  if (/^(ktrt|kt|tk|rt|rk)1p[a-zA-Z0-9]{58}$/i.test(trimmed)) {
    return trimmed.toLowerCase()
  }
  return trimmed
}

/**
 * Validates KristaTech destination addresses across Mainnet ('main'), Testnet ('test'), and Regtest ('regtest').
 * Verifies both Base58Check 4-byte double-SHA256 checksums and BIP-350 Bech32m Taproot checksums.
 */
export function isValidKristaAddress(address: unknown, chain?: string): boolean {
  if (typeof address !== 'string') return false
  const trimmed = address.trim()
  if (trimmed.length < 24 || trimmed.length > 64) return false

  // Reject mixed-case Bech32m strings per BIP-173/BIP-350
  if (/^(ktrt|kt|tk|rt|rk)1p/i.test(trimmed)) {
    if (trimmed !== trimmed.toLowerCase() && trimmed !== trimmed.toUpperCase()) {
      return false
    }
  }

  const normalized = normalizeTaprootAddress(trimmed)
  const normChain = (chain || '').toLowerCase()

  // Check Bech32m Taproot format (kt1p..., tk1p..., rt1p..., rk1p..., ktrt1p...)
  const taprootMatch = normalized.match(/^(ktrt|kt|tk|rt|rk)1p[ac-hj-np-z02-9]{58}$/)
  if (taprootMatch) {
    const hrp = taprootMatch[1] as 'kt' | 'tk' | 'rt' | 'rk' | 'ktrt'
    if (normChain === 'main' && hrp !== 'kt') return false
    if ((normChain === 'test' || normChain === 'regtest') && hrp === 'kt') return false
    return verifyBech32mTaprootChecksum(normalized, hrp)
  }

  // Check Base58Check format (KT... on Mainnet, kt... on Testnet/Regtest)
  if (!/^(KT|kt)[1-9A-HJ-NP-Za-km-z]{22,44}$/.test(trimmed)) {
    return false
  }
  if (normChain === 'main' && !trimmed.startsWith('KT')) return false
  if ((normChain === 'test' || normChain === 'regtest') && !trimmed.startsWith('kt')) return false

  try {
    const decoded = decodeBase58(trimmed)
    // KristaTech uses 2-byte Base58 prefixes + 20-byte hash160 + 4-byte checksum = 26 bytes
    if (decoded.length < 25 || decoded.length > 28) return false
    const payload = decoded.slice(0, decoded.length - 4)
    const checksum = decoded.slice(decoded.length - 4)
    const expected = doubleSha256Bytes(payload).slice(0, 4)
    for (let i = 0; i < 4; i++) {
      if (checksum[i] !== expected[i]) return false
    }
    return true
  } catch {
    return false
  }
}

export function blsPubKeysMatch(pkHexA: string, pkHexB: string): boolean {
  const cleanA = String(pkHexA || '').trim().toLowerCase()
  const cleanB = String(pkHexB || '').trim().toLowerCase()
  return /^[0-9a-f]{96}$/.test(cleanA) && cleanA === cleanB
}

export function pubkeysMatch(pkHexA: string, pkHexB: string): boolean {
  try {
    const cleanA = String(pkHexA || '').trim().toLowerCase()
    const cleanB = String(pkHexB || '').trim().toLowerCase()
    if (!cleanA || !cleanB) return false
    if (/^[0-9a-f]{96}$/.test(cleanA) || /^[0-9a-f]{96}$/.test(cleanB)) {
      return false
    }
    const normA = bytesToHex(secp256k1.ProjectivePoint.fromHex(cleanA).toRawBytes(true)).toLowerCase()
    const normB = bytesToHex(secp256k1.ProjectivePoint.fromHex(cleanB).toRawBytes(true)).toLowerCase()
    return normA === normB
  } catch {
    return false
  }
}

export function writeCompactSizeBytes(size: number): Uint8Array {
  if (!Number.isInteger(size) || size < 0) {
    throw new Error('Invalid compact size value')
  }
  if (size < 253) {
    return new Uint8Array([size])
  } else if (size <= 0xffff) {
    return new Uint8Array([253, size & 0xff, (size >>> 8) & 0xff])
  } else if (size <= 0xffffffff) {
    return new Uint8Array([
      254,
      size & 0xff,
      (size >>> 8) & 0xff,
      (size >>> 16) & 0xff,
      (size >>> 24) & 0xff
    ])
  } else {
    const low = size >>> 0
    const high = Math.floor(size / 0x100000000) >>> 0
    return new Uint8Array([
      255,
      low & 0xff,
      (low >>> 8) & 0xff,
      (low >>> 16) & 0xff,
      (low >>> 24) & 0xff,
      high & 0xff,
      (high >>> 8) & 0xff,
      (high >>> 16) & 0xff,
      (high >>> 24) & 0xff
    ])
  }
}

export function readCompactSizeBytes(
  buf: Uint8Array,
  offset: number
): { value: number; size: number } {
  if (offset < 0 || offset >= buf.length) {
    throw new Error('CompactSize offset out of bounds')
  }
  const first = buf[offset]!
  if (first < 253) {
    return { value: first, size: 1 }
  } else if (first === 253) {
    if (offset + 3 > buf.length) throw new Error('Truncated 16-bit CompactSize')
    const value = buf[offset + 1]! | (buf[offset + 2]! << 8)
    return { value, size: 3 }
  } else if (first === 254) {
    if (offset + 5 > buf.length) throw new Error('Truncated 32-bit CompactSize')
    const value =
      (buf[offset + 1]! |
        (buf[offset + 2]! << 8) |
        (buf[offset + 3]! << 16) |
        (buf[offset + 4]! << 24)) >>>
      0
    return { value, size: 5 }
  } else {
    if (offset + 9 > buf.length) throw new Error('Truncated 64-bit CompactSize')
    const low =
      (buf[offset + 1]! |
        (buf[offset + 2]! << 8) |
        (buf[offset + 3]! << 16) |
        (buf[offset + 4]! << 24)) >>>
      0
    const high =
      (buf[offset + 5]! |
        (buf[offset + 6]! << 8) |
        (buf[offset + 7]! << 16) |
        (buf[offset + 8]! << 24)) >>>
      0
    return { value: high * 0x100000000 + low, size: 9 }
  }
}

export function getPushDataPrefixBytes(length: number): Uint8Array {
  if (length < 76) {
    return new Uint8Array([length])
  } else if (length <= 255) {
    return new Uint8Array([76, length])
  } else if (length <= 65535) {
    return new Uint8Array([77, length & 0xff, (length >>> 8) & 0xff])
  } else {
    return new Uint8Array([
      78,
      length & 0xff,
      (length >>> 8) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 24) & 0xff
    ])
  }
}

export function extractScriptSigPushesStrict(scriptSigHex: string): {
  valid: boolean
  pushes: Uint8Array[]
  error?: string
} {
  const clean = String(scriptSigHex || '').trim()
  if (!clean) {
    return { valid: false, pushes: [], error: 'Empty scriptSig' }
  }
  let buf: Uint8Array
  try {
    buf = hexToBytes(clean)
  } catch {
    return { valid: false, pushes: [], error: 'Invalid scriptSig hex' }
  }

  const pushes: Uint8Array[] = []
  let i = 0
  while (i < buf.length) {
    const op = buf[i]!
    i += 1
    let len = 0
    if (op >= 1 && op <= 75) {
      len = op
    } else if (op === 76) {
      if (i + 1 > buf.length) {
        return { valid: false, pushes: [], error: 'Truncated OP_PUSHDATA1 length in scriptSig' }
      }
      len = buf[i]!
      i += 1
      if (len < 76) {
        return { valid: false, pushes: [], error: 'Non-minimal OP_PUSHDATA1 push in scriptSig' }
      }
    } else if (op === 77) {
      if (i + 2 > buf.length) {
        return { valid: false, pushes: [], error: 'Truncated OP_PUSHDATA2 length in scriptSig' }
      }
      len = buf[i]! | (buf[i + 1]! << 8)
      i += 2
      if (len <= 255) {
        return { valid: false, pushes: [], error: 'Non-minimal OP_PUSHDATA2 push in scriptSig' }
      }
    } else if (op === 78) {
      if (i + 4 > buf.length) {
        return { valid: false, pushes: [], error: 'Truncated OP_PUSHDATA4 length in scriptSig' }
      }
      len = (buf[i]! | (buf[i + 1]! << 8) | (buf[i + 2]! << 16) | (buf[i + 3]! << 24)) >>> 0
      i += 4
      if (len <= 65535) {
        return { valid: false, pushes: [], error: 'Non-minimal OP_PUSHDATA4 push in scriptSig' }
      }
    } else {
      return {
        valid: false,
        pushes: [],
        error: `Disallowed non-push opcode 0x${op.toString(16)} in scriptSig`
      }
    }
    if (i + len > buf.length) {
      return { valid: false, pushes: [], error: 'Truncated push data in scriptSig' }
    }
    pushes.push(buf.subarray(i, i + len))
    i += len
  }

  if (i !== buf.length) {
    return { valid: false, pushes: [], error: 'Unconsumed trailing bytes in scriptSig' }
  }
  return { valid: true, pushes }
}

export function extractScriptSigPushesBytes(scriptSigHex: string): Uint8Array[] {
  const res = extractScriptSigPushesStrict(scriptSigHex)
  return res.valid ? res.pushes : []
}

/**
 * Parses input outpoints (`txid:vout` with canonical reversed 32-byte txid) from raw transaction hex.
 */
export function extractInputOutpoints(rawTxHex: string): string[] {
  try {
    const txBuf = hexToBytes(rawTxHex)
    if (txBuf.length < 10) return []
    let offset = 4
    const vinCountInfo = readCompactSizeBytes(txBuf, offset)
    offset += vinCountInfo.size
    const outpoints: string[] = []
    for (let i = 0; i < vinCountInfo.value; i++) {
      if (offset + 36 > txBuf.length) return []
      const txid = bytesToHex(new Uint8Array(txBuf.subarray(offset, offset + 32)).reverse())
      offset += 32
      const vout =
        (txBuf[offset]! |
          (txBuf[offset + 1]! << 8) |
          (txBuf[offset + 2]! << 16) |
          (txBuf[offset + 3]! << 24)) >>>
        0
      offset += 4
      const scriptLenInfo = readCompactSizeBytes(txBuf, offset)
      offset += scriptLenInfo.size + scriptLenInfo.value + 4
      if (offset > txBuf.length) return []
      outpoints.push(`${txid}:${vout}`)
    }
    return outpoints
  } catch {
    return []
  }
}

export function computeSighashAllBytes(
  rawTxHex: string,
  inputIndex: number,
  scriptCode: Uint8Array
): Uint8Array {
  const txBuf = hexToBytes(rawTxHex)
  let offset = 0

  if (txBuf.length < 10) {
    throw new Error('Transaction buffer too short')
  }

  const version = txBuf.subarray(offset, offset + 4)
  offset += 4

  const vinCountInfo = readCompactSizeBytes(txBuf, offset)
  const vinCountBuf = txBuf.subarray(offset, offset + vinCountInfo.size)
  offset += vinCountInfo.size

  if (inputIndex < 0 || inputIndex >= vinCountInfo.value) {
    throw new Error(`Input index ${inputIndex} out of range (vin count: ${vinCountInfo.value})`)
  }

  const parts: Uint8Array[] = [version, vinCountBuf]

  for (let i = 0; i < vinCountInfo.value; i++) {
    if (offset + 36 > txBuf.length) {
      throw new Error('Truncated transaction input prevout')
    }
    const prevout = txBuf.subarray(offset, offset + 36)
    offset += 36

    const scriptSigLenInfo = readCompactSizeBytes(txBuf, offset)
    offset += scriptSigLenInfo.size + scriptSigLenInfo.value

    if (offset + 4 > txBuf.length) {
      throw new Error('Truncated transaction input nSequence')
    }
    const nSequence = txBuf.subarray(offset, offset + 4)
    offset += 4

    if (i === inputIndex) {
      parts.push(prevout, writeCompactSizeBytes(scriptCode.length), scriptCode, nSequence)
    } else {
      parts.push(prevout, new Uint8Array([0x00]), nSequence)
    }
  }

  // Remaining bytes (vout + nLockTime) + 4-byte little-endian SIGHASH_ALL (0x01000000)
  parts.push(txBuf.subarray(offset), new Uint8Array([0x01, 0x00, 0x00, 0x00]))
  return doubleSha256Bytes(concatBytes(...parts))
}

export function verifySporkInputSignature(
  rawTxHex: string,
  inputIndex: number,
  sigPush: Uint8Array,
  pubKeyPush: Uint8Array,
  sporkPubKeyHex: string
): { valid: boolean; error?: string } {
  try {
    if (bytesToHex(pubKeyPush).toLowerCase() !== sporkPubKeyHex.trim().toLowerCase()) {
      return {
        valid: false,
        error: 'Input scriptSig public key does not match consensus Spork public key'
      }
    }
    if (sigPush.length < 9 || sigPush.length > 73) {
      return { valid: false, error: `Invalid Spork ECDSA signature length (${sigPush.length})` }
    }
    const nHashType = sigPush[sigPush.length - 1]!
    if (nHashType !== 0x01) {
      return {
        valid: false,
        error: `Invalid Spork signature hash type (0x${nHashType.toString(16)}); SIGHASH_ALL (0x01) is required`
      }
    }
    const derSig = sigPush.subarray(0, sigPush.length - 1)

    const sporkPubKeyBuf = hexToBytes(sporkPubKeyHex)
    const sporkScriptCode = concatBytes(
      hexToBytes('76a914'),
      hash160Bytes(sporkPubKeyBuf),
      hexToBytes('88ac')
    )

    const sighashSpork = computeSighashAllBytes(rawTxHex, inputIndex, sporkScriptCode)
    if (secp256k1.verify(derSig, sighashSpork, sporkPubKeyBuf, { lowS: true })) {
      return { valid: true }
    }

    return { valid: false, error: 'Cryptographic verification of Spork ECDSA signature failed' }
  } catch (err: any) {
    return { valid: false, error: `Spork signature verification error: ${err.message}` }
  }
}

/**
 * Builds a hybrid CBLSSignedData (blsPubKey[48B] + blsSig[96B] + compactSize + ecdsaSig[DER])
 * matching CQuorumSignature::Verify in src/llmq.cpp:43-108.
 * Zeroes out intermediate secret key byte buffers before returning.
 */
export function createHybridBLSSignedData(
  privKeyHex: string,
  txHashHex: string
): {
  signedDataHex: string
  blsPubKeyHex: string
  blsSigHex: string
  compressedPubKey: string
} {
  const privKeyBytes = hexToBytes(privKeyHex)
  if (privKeyBytes.length !== 32) {
    privKeyBytes.fill(0)
    throw new Error('Private key must be 32 bytes')
  }
  const msgBlockHash = hexToBytes(txHashHex).reverse()
  if (msgBlockHash.length !== 32) {
    privKeyBytes.fill(0)
    throw new Error('Proposal txHash must be 32 bytes (64 hex chars)')
  }

  const seedInput = new Uint8Array(privKeyBytes.length + msgBlockHash.length)
  let blsPrivKey: Uint8Array | null = null

  try {
    const compressedPubKey = bytesToHex(secp256k1.getPublicKey(privKeyBytes, true)).toLowerCase()

    seedInput.set(privKeyBytes, 0)
    seedInput.set(msgBlockHash, privKeyBytes.length)
    blsPrivKey = doubleSha256Bytes(seedInput)
    blsPrivKey[0]! &= 0x3f // Ensure scalar < BLS12-381 curve order r
    if (blsPrivKey.every((b) => b === 0)) {
      blsPrivKey[31] = 1
    }

    const blsPubKey = bls12_381.getPublicKey(blsPrivKey) // 48 bytes
    const blsSig = bls12_381.sign(msgBlockHash, blsPrivKey, { DST: BLS_DST }) // 96 bytes

    // Sign Hash(blsPubKey) (double-SHA256) with Masternode secp256k1 key (low-S canonical DER)
    const hashPubKey = doubleSha256Bytes(blsPubKey)
    const ecdsaSig = secp256k1.sign(hashPubKey, privKeyBytes, { lowS: true })
    const ecdsaDerBytes = ecdsaSig.toDERRawBytes()
    const ecdsaCompactLen = writeCompactSizeBytes(ecdsaDerBytes.length)

    const signedDataBytes = concatBytes(blsPubKey, blsSig, ecdsaCompactLen, ecdsaDerBytes)

    return {
      signedDataHex: bytesToHex(signedDataBytes),
      blsPubKeyHex: bytesToHex(blsPubKey),
      blsSigHex: bytesToHex(blsSig),
      compressedPubKey
    }
  } finally {
    privKeyBytes.fill(0)
    seedInput.fill(0)
    if (blsPrivKey) {
      blsPrivKey.fill(0)
    }
  }
}

/**
 * Derives the compressed 48-byte BLS12-381 G1 public key (96 hex chars) from a
 * 32-byte KTDIP3 operator secret key (64 hex chars). Zeroes ephemeral buffers.
 */
export function deriveBlsPubKeyFromSecret(blsSecretHex: string): {
  blsSecretHex: string
  blsPubKeyHex: string
} {
  const clean = String(blsSecretHex || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error('KTDIP3 BLS operator secret key must be 64 hex characters (32 bytes)')
  }
  const secretBytes = hexToBytes(clean)
  try {
    const pubBytes = bls12_381.getPublicKey(secretBytes)
    return {
      blsSecretHex: clean,
      blsPubKeyHex: bytesToHex(pubBytes)
    }
  } finally {
    secretBytes.fill(0)
  }
}

/**
 * Deterministically derives the default KTDIP3 32-byte BLS12-381 operator keypair from
 * a 32-byte secp256k1 private key using IETF BLS Draft v4 HKDF-SHA256 (blst_keygen),
 * matching DeriveBLSFromCKey in src/crypto/bls.cpp:235-255. Zeroes ephemeral buffers.
 */
export function deriveDip3BlsKeyFromEcdsaPrivKey(privKeyHex: string): {
  blsSecretHex: string
  blsPubKeyHex: string
} {
  const privKeyBytes = hexToBytes(privKeyHex)
  if (privKeyBytes.length !== 32) {
    privKeyBytes.fill(0)
    throw new Error('Private key must be 32 bytes')
  }

  const ikm = concatBytes(privKeyBytes, new Uint8Array([0x00]))
  const info = new Uint8Array([0x00, 0x30]) // I2OSP(48, 2)
  let salt: Uint8Array = sha256(new TextEncoder().encode('BLS-SIG-KEYGEN-SALT-'))
  let blsSecretHex = ''

  try {
    for (let attempt = 0; attempt < 16; attempt++) {
      const prk = hkdfExtract(sha256, ikm, salt)
      const okm = hkdfExpand(sha256, prk, info, 48)
      try {
        const skBigInt = BigInt('0x' + bytesToHex(okm)) % bls12_381.params.r
        if (skBigInt !== 0n) {
          blsSecretHex = skBigInt.toString(16).padStart(64, '0')
          break
        }
      } finally {
        prk.fill(0)
        okm.fill(0)
      }
      salt = sha256(salt)
    }

    if (!blsSecretHex) {
      throw new Error('Failed to derive non-zero BLS12-381 scalar via blst_keygen')
    }

    const secretBytes = hexToBytes(blsSecretHex)
    try {
      const pubBytes = bls12_381.getPublicKey(secretBytes)
      return {
        blsSecretHex,
        blsPubKeyHex: bytesToHex(pubBytes)
      }
    } finally {
      secretBytes.fill(0)
    }
  } finally {
    privKeyBytes.fill(0)
    ikm.fill(0)
    salt.fill(0)
  }
}

/**
 * Builds a KTDIP3 pure operator CBLSSignedData (48B blsPubKey + 96B blsSig + 0x00, 145 bytes)
 * matching SignBLSOperatorOnly / CQuorumSignature::Verify in src/llmq.cpp.
 */
export function createOperatorBLSSignedData(
  blsSecretHex: string,
  txHashHex: string
): {
  signedDataHex: string
  blsPubKeyHex: string
  blsSigHex: string
} {
  const cleanSecret = String(blsSecretHex || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(cleanSecret)) {
    throw new Error('BLS operator secret key must be 32 bytes (64 hex chars)')
  }
  const secretBytes = hexToBytes(cleanSecret)
  const msgBlockHash = hexToBytes(txHashHex).reverse()
  if (msgBlockHash.length !== 32) {
    secretBytes.fill(0)
    throw new Error('Proposal txHash must be 32 bytes (64 hex chars)')
  }
  try {
    const blsPubKey = bls12_381.getPublicKey(secretBytes) // 48 bytes
    const blsSig = bls12_381.sign(msgBlockHash, secretBytes, { DST: BLS_DST }) // 96 bytes
    const signedDataBytes = concatBytes(blsPubKey, blsSig, new Uint8Array([0x00]))
    return {
      signedDataHex: bytesToHex(signedDataBytes),
      blsPubKeyHex: bytesToHex(blsPubKey),
      blsSigHex: bytesToHex(blsSig)
    }
  } finally {
    secretBytes.fill(0)
  }
}

export function verifyAndParseBLSSignedData(
  sigHex: string,
  txHashHex: string,
  memberPubkeyHex: string,
  operatorPubKeyHex?: string
): { valid: boolean; error?: string; blsPubKey?: Uint8Array; blsSig?: Uint8Array; mode?: 'dip3-operator' | 'hybrid' } {
  try {
    const sigBuf = hexToBytes(sigHex)
    // Minimum size: 145 (KTDIP3 operator-only: 48B pk + 96B sig + 0x00) or 209+ (hybrid with DER ECDSA)
    if (sigBuf.length !== 145 && (sigBuf.length < 209 || sigBuf.length > 512)) {
      return {
        valid: false,
        error: `Invalid CBLSSignedData byte length (${sigBuf.length}); expected 145B KTDIP3 operator or >=209B hybrid`
      }
    }

    const blsPubKey = sigBuf.subarray(0, 48)
    const blsSig = sigBuf.subarray(48, 144)
    const ecdsaLenInfo = readCompactSizeBytes(sigBuf, 144)
    const expectedTotal = 144 + ecdsaLenInfo.size + ecdsaLenInfo.value
    if (expectedTotal !== sigBuf.length) {
      return { valid: false, error: 'Malformed CBLSSignedData compactSize for ecdsaSig' }
    }

    const sigBlsPkHex = bytesToHex(blsPubKey)
    const expectedOperatorPk =
      (operatorPubKeyHex && /^[0-9a-fA-F]{96}$/.test(operatorPubKeyHex.trim())
        ? operatorPubKeyHex.trim()
        : '') ||
      (/^[0-9a-fA-F]{96}$/.test(memberPubkeyHex.trim()) ? memberPubkeyHex.trim() : '')

    let mode: 'dip3-operator' | 'hybrid'
    if (expectedOperatorPk) {
      // KTDIP3 consensus strictly requires 145B pure-operator CBLSSignedData (48B pk + 96B sig + 0x00)
      if (sigBuf.length !== 145 || ecdsaLenInfo.value !== 0) {
        return {
          valid: false,
          error:
            'KTDIP3 masternode requires 145B pure operator BLS signature (trailing ECDSA/hybrid payload is rejected)'
        }
      }
      if (!blsPubKeysMatch(sigBlsPkHex, expectedOperatorPk)) {
        return {
          valid: false,
          error: 'BLS operator public key does not match registered KTDIP3 masternode operator key'
        }
      }
      mode = 'dip3-operator'
    } else if (ecdsaLenInfo.value === 0) {
      return {
        valid: false,
        error: 'KTDIP3 operator-only BLS signature requires registered 48B BLS operator public key'
      }
    } else {
      // Legacy / Hybrid BLS12-381 + ECDSA mode (vchEcdsaSig non-empty)
      mode = 'hybrid'
      const ecdsaSig = sigBuf.subarray(144 + ecdsaLenInfo.size, expectedTotal)
      const hashPubKey = doubleSha256Bytes(blsPubKey)
      const memberPubBytes = hexToBytes(memberPubkeyHex.trim())
      if (!secp256k1.verify(ecdsaSig, hashPubKey, memberPubBytes, { lowS: true })) {
        return {
          valid: false,
          error: 'Invalid Masternode ECDSA authorization signature over Hash(blsPubKey)'
        }
      }
    }

    // Verify BLS12-381 signature over blockHash.begin() (32-byte little-endian internal uint256)
    const msgBlockHash = hexToBytes(txHashHex).reverse()
    const blsOk = bls12_381.verify(new Uint8Array(blsSig), msgBlockHash, new Uint8Array(blsPubKey), {
      DST: BLS_DST
    })
    if (!blsOk) {
      return { valid: false, error: 'Invalid BLS12-381 signature over proposal txHash' }
    }

    return {
      valid: true,
      mode,
      blsPubKey: new Uint8Array(blsPubKey),
      blsSig: new Uint8Array(blsSig)
    }
  } catch (err: any) {
    return { valid: false, error: `CBLSSignedData verification failed: ${err.message}` }
  }
}

export function verifyAggregatedBLSSignatures(
  txHashHex: string,
  signatures: Array<{ pubkey: string; operatorPubKey?: string; signature: string }>
): { valid: boolean; error?: string } {
  try {
    if (!Array.isArray(signatures) || signatures.length === 0) {
      return { valid: false, error: 'No signatures to aggregate' }
    }
    const parsedPks: Uint8Array[] = []
    const parsedSigs: Uint8Array[] = []
    const seenBlsPks = new Set<string>()
    for (const item of signatures) {
      const p = verifyAndParseBLSSignedData(
        item.signature,
        txHashHex,
        item.pubkey,
        item.operatorPubKey
      )
      if (!p.valid || !p.blsPubKey || !p.blsSig) {
        return { valid: false, error: p.error || 'Invalid member signature in aggregation set' }
      }
      const pkHex = bytesToHex(p.blsPubKey)
      if (seenBlsPks.has(pkHex)) {
        return {
          valid: false,
          error: 'Duplicate BLS operator public key in quorum signature set'
        }
      }
      seenBlsPks.add(pkHex)
      parsedPks.push(p.blsPubKey)
      parsedSigs.push(p.blsSig)
    }
    const aggPk = bls12_381.aggregatePublicKeys(parsedPks)
    const aggSig = bls12_381.aggregateSignatures(parsedSigs)
    const msgBlockHash = hexToBytes(txHashHex).reverse()
    if (!bls12_381.verify(aggSig, msgBlockHash, aggPk, { DST: BLS_DST })) {
      return { valid: false, error: 'Aggregated BLS12-381 quorum signature verification failed' }
    }
    return { valid: true }
  } catch (err: any) {
    return { valid: false, error: `BLS aggregation failed: ${err.message}` }
  }
}

export function serializeQuorumSignatureBytes(
  txHashHex: string,
  sigs: Array<{ txhash: string; outidx: number; signature: string }>
): Uint8Array {
  const blockHashBuf = hexToBytes(txHashHex).reverse()
  const parts: Uint8Array[] = [blockHashBuf, writeCompactSizeBytes(sigs.length)]

  for (const item of sigs) {
    const txhashBuf = hexToBytes(item.txhash).reverse()
    const outidxBuf = new Uint8Array(4)
    const outIdxVal = Number(item.outidx) >>> 0
    outidxBuf[0] = outIdxVal & 0xff
    outidxBuf[1] = (outIdxVal >>> 8) & 0xff
    outidxBuf[2] = (outIdxVal >>> 16) & 0xff
    outidxBuf[3] = (outIdxVal >>> 24) & 0xff
    const sigBuf = hexToBytes(item.signature)

    parts.push(txhashBuf, outidxBuf, writeCompactSizeBytes(sigBuf.length), sigBuf)
  }

  return concatBytes(...parts)
}

export function injectQuorumSigIntoRawTxBytes(
  rawTxHex: string,
  qsigPush: Uint8Array
): Uint8Array {
  const txBuf = hexToBytes(rawTxHex)
  let offset = 0

  const version = txBuf.subarray(offset, offset + 4)
  offset += 4

  const vinCountInfo = readCompactSizeBytes(txBuf, offset)
  const vinCountBuf = txBuf.subarray(offset, offset + vinCountInfo.size)
  offset += vinCountInfo.size

  const parts: Uint8Array[] = [version, vinCountBuf]

  for (let i = 0; i < vinCountInfo.value; i++) {
    const prevout = txBuf.subarray(offset, offset + 36)
    offset += 36

    const scriptSigLenInfo = readCompactSizeBytes(txBuf, offset)
    offset += scriptSigLenInfo.size
    const originalScriptSig = txBuf.subarray(offset, offset + scriptSigLenInfo.value)
    offset += scriptSigLenInfo.value

    const nSequence = txBuf.subarray(offset, offset + 4)
    offset += 4

    const newScriptSig = concatBytes(originalScriptSig, qsigPush)
    parts.push(prevout, writeCompactSizeBytes(newScriptSig.length), newScriptSig, nSequence)
  }

  parts.push(txBuf.subarray(offset))
  return concatBytes(...parts)
}

export function maskIpAddress(ip: string | undefined): string {
  if (!ip) return 'On-Chain MN'
  const trimmed = String(ip).trim()
  if (!trimmed) return 'On-Chain MN'
  if (trimmed.startsWith('ADAM-Miner')) return trimmed
  if (
    trimmed === 'On-Chain MN' ||
    trimmed === '0.0.0.0:0' ||
    trimmed === '0.0.0.0' ||
    trimmed === '[::]:0' ||
    trimmed === '::'
  ) {
    return 'On-Chain MN'
  }
  if (!trimmed.includes('.') && !trimmed.includes(':')) {
    return 'On-Chain MN'
  }
  const lastColon = trimmed.lastIndexOf(':')
  const isIpv6Bracket = trimmed.startsWith('[')
  if (isIpv6Bracket || (trimmed.includes(':') && !trimmed.includes('.'))) {
    const portMatch = trimmed.match(/\]:(\d+)$/)
    const portSuffix = portMatch ? `:${portMatch[1]}` : ''
    return `[xxxx:xxxx:xxxx::xxxx]${portSuffix}`
  }

  const ipPart = lastColon !== -1 ? trimmed.slice(0, lastColon) : trimmed
  const portPart = lastColon !== -1 ? trimmed.slice(lastColon) : ''

  if (ipPart.includes('.')) {
    const octets = ipPart.split('.')
    if (octets.length === 4) {
      return `${octets[0]}.xxx.xxx.${octets[3]}${portPart}`
    }
    return `xxx.xxx.xxx.xxx${portPart}`
  }
  return `[xxxx:xxxx:xxxx::xxxx]${portPart}`
}
