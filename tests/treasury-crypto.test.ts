import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { secp256k1 } from '@noble/curves/secp256k1'
import {
  CHAIN_DEFAULTS,
  CORE_VERSION,
  PROTOCOL_VERSION,
  QUORUM_EQUIVOCATION_GUARD_SECS,
  hexToBytes,
  bytesToHex,
  doubleSha256Bytes,
  hash160Bytes,
  calculateTxHash,
  encodeBase58Check,
  getRawPrivateKeyFromWIF,
  derivePubKeysFromWIF,
  getTargetQuorumSize,
  getQuorumMajorityThreshold,
  isValidKristaAddress,
  normalizeTaprootAddress,
  pubkeysMatch,
  writeCompactSizeBytes,
  readCompactSizeBytes,
  getPushDataPrefixBytes,
  extractInputOutpoints,
  extractScriptSigPushesBytes,
  extractScriptSigPushesStrict,
  computeSighashAllBytes,
  verifySporkInputSignature,
  deriveBlsPubKeyFromSecret,
  deriveDip3BlsKeyFromEcdsaPrivKey,
  createOperatorBLSSignedData,
  createHybridBLSSignedData,
  verifyAndParseBLSSignedData,
  verifyAggregatedBLSSignatures,
  serializeQuorumSignatureBytes,
  injectQuorumSigIntoRawTxBytes,
  maskIpAddress
} from '../app/utils/treasuryCrypto.ts'

function createTestWif(secretByte: number, compressed = true, version = 0x80): string {
  const privKey = new Uint8Array(32).fill(secretByte)
  const payload = new Uint8Array(compressed ? 34 : 33)
  payload[0] = version
  payload.set(privKey, 1)
  if (compressed) {
    payload[33] = 0x01
  }
  return encodeBase58Check(payload)
}

function createTestKristaAddress(pubKeyBytes: Uint8Array, prefixBytes: [number, number]): string {
  const h160 = hash160Bytes(pubKeyBytes)
  const payload = new Uint8Array(22)
  payload[0] = prefixBytes[0]
  payload[1] = prefixBytes[1]
  payload.set(h160, 2)
  return encodeBase58Check(payload)
}

describe('treasuryCrypto — Encoding, WIF & Address Validation', () => {
  it('encodes and decodes Base58Check and WIF keys with strict checksum validation', () => {
    const wif = createTestWif(0x11, true, 0x80)
    const rawKeyHex = getRawPrivateKeyFromWIF(wif)
    assert.equal(rawKeyHex.length, 64)
    assert.equal(rawKeyHex.slice(0, 2), '11')

    const derived = derivePubKeysFromWIF(wif)
    assert.ok(derived)
    assert.equal(derived.compressedPubKey.length, 66)
    assert.equal(derived.uncompressedPubKey.length, 130)
    assert.equal(pubkeysMatch(derived.compressedPubKey, derived.uncompressedPubKey), true)

    // Tamper last character of WIF -> must fail Base58Check checksum
    const lastChar = wif[wif.length - 1] === 'A' ? 'B' : 'A'
    const tamperedWif = wif.slice(0, -1) + lastChar
    assert.throws(() => derivePubKeysFromWIF(tamperedWif), /checksum|Invalid WIF/i)
    assert.throws(() => getRawPrivateKeyFromWIF(tamperedWif), /checksum|Invalid WIF/i)

    // Accept Krista Mainnet (0x2b), Legacy (0x80), and Testnet/Regtest (0xef) WIF version bytes
    for (const prefix of [0x2b, 0x80, 0xef]) {
      const validWif = createTestWif(0x12, true, prefix)
      assert.equal(getRawPrivateKeyFromWIF(validWif), '12'.repeat(32))
    }

    // Reject unknown WIF version prefix byte
    const badPrefixWif = createTestWif(0x12, true, 0x99)
    assert.throws(() => getRawPrivateKeyFromWIF(badPrefixWif), /prefix/i)

    // Reject out-of-range secp256k1 private key scalar (>= CURVE.n)
    const highScalarPayload = new Uint8Array(34)
    highScalarPayload[0] = 0x80
    highScalarPayload.fill(0xff, 1, 33)
    highScalarPayload[33] = 0x01
    const highScalarWif = encodeBase58Check(highScalarPayload)
    assert.throws(() => getRawPrivateKeyFromWIF(highScalarWif), /out-of-range|Invalid/i)
  })

  it('validates Krista Base58Check (KT... / kt...) addresses and rejects tampered checksums', () => {
    // Official Mainnet & Testnet Developer Fund addresses from CHAIN_DEFAULTS
    assert.equal(isValidKristaAddress('KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP', 'main'), true)
    assert.equal(isValidKristaAddress('ktEooARF3HdV8w59LUc5jaHrS7GBL7974Uy', 'test'), true)
    assert.equal(isValidKristaAddress('kt5KNitasi4bEHbQQCrpy6445nJD7uSVNux', 'regtest'), true)
    assert.equal(isValidKristaAddress('KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP', 'test'), false)

    // Tamper checksum on Base58Check address
    assert.equal(isValidKristaAddress('KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoQ', 'main'), false)
    assert.equal(isValidKristaAddress('invalid_address_string'), false)
    assert.equal(isValidKristaAddress(''), false)
  })

  it('computes reversed Double-SHA256 transaction hashes accurately', () => {
    const rawHex =
      '0200000001' +
      '11'.repeat(32) +
      '00000000' +
      '00' +
      'ffffffff' +
      '01' +
      '00e1f50500000000' +
      '1976a914' +
      '22'.repeat(20) +
      '88ac' +
      '00000000'
    const txHash = calculateTxHash(rawHex)
    assert.equal(txHash.length, 64)
    assert.match(txHash, /^[0-9a-f]{64}$/)
    const manualDigest = bytesToHex(Uint8Array.from(doubleSha256Bytes(hexToBytes(rawHex))).reverse())
    assert.equal(txHash, manualDigest)
  })

  it('masks IPv4 and IPv6 service addresses while preserving port', () => {
    assert.equal(maskIpAddress('185.122.44.91:19999'), '185.xxx.xxx.91:19999')
    assert.equal(maskIpAddress('10.0.0.1'), '10.xxx.xxx.1')
    assert.equal(maskIpAddress(''), 'On-Chain MN')
    assert.equal(maskIpAddress('0.0.0.0:0'), 'On-Chain MN')
    assert.equal(maskIpAddress('[::]:0'), 'On-Chain MN')
    assert.equal(maskIpAddress('KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP'), 'On-Chain MN')
  })

  it('enforces Krista Core v1.5.9.0 (Proto 70983) dynamic LLMQ scaling (5->9->11->15), majority thresholds, and governance start heights', () => {
    assert.equal(CORE_VERSION, 'v1.5.9.0')
    assert.equal(PROTOCOL_VERSION, 70983)
    assert.equal(QUORUM_EQUIVOCATION_GUARD_SECS, 30)

    assert.equal(CHAIN_DEFAULTS.main?.treasuryGovernanceStartHeight, 5000)
    assert.equal(CHAIN_DEFAULTS.test?.treasuryGovernanceStartHeight, 200)
    assert.equal(CHAIN_DEFAULTS.regtest?.treasuryGovernanceStartHeight, 100)

    // Dynamic LLMQ Quorum Scaling (src/llmq.cpp:GetTargetQuorumSize)
    assert.equal(getTargetQuorumSize(0), 5)
    assert.equal(getTargetQuorumSize(4), 5)
    assert.equal(getTargetQuorumSize(24), 5)
    assert.equal(getTargetQuorumSize(25), 9)
    assert.equal(getTargetQuorumSize(49), 9)
    assert.equal(getTargetQuorumSize(50), 11)
    assert.equal(getTargetQuorumSize(99), 11)
    assert.equal(getTargetQuorumSize(100), 15)
    assert.equal(getTargetQuorumSize(250), 15)

    // Majority thresholds (3/5, 5/9, 6/11, 8/15)
    assert.equal(getQuorumMajorityThreshold(5), 3)
    assert.equal(getQuorumMajorityThreshold(9), 5)
    assert.equal(getTargetQuorumSize(50), 11)
    assert.equal(getQuorumMajorityThreshold(11), 6)
    assert.equal(getQuorumMajorityThreshold(15), 8)
    assert.equal(getQuorumMajorityThreshold(2), 2)

    // Taproot normalization (lowercases 62-char Bech32m while preserving Base58Check case)
    assert.equal(
      normalizeTaprootAddress('KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP'),
      'KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP'
    )
    const upperTaproot = 'KT1P' + 'Q'.repeat(58)
    assert.equal(normalizeTaprootAddress(upperTaproot), upperTaproot.toLowerCase())
  })
})

describe('treasuryCrypto — CompactSize, Script Push, Spork SIGHASH_ALL & Hybrid BLS Quorum', () => {
  it('round-trips CompactSize integers across 1-byte, 3-byte, and 5-byte boundaries', () => {
    for (const val of [0, 1, 252, 253, 1024, 65535, 70000]) {
      const encoded = writeCompactSizeBytes(val)
      const decoded = readCompactSizeBytes(encoded, 0)
      assert.equal(decoded.value, val)
      assert.equal(decoded.size, encoded.length)
    }
  })

  it('creates and verifies Spork SIGHASH_ALL input signatures and Hybrid BLS Quorum signatures', () => {
    const sporkPrivHex = '33'.repeat(32)
    const sporkPrivBytes = hexToBytes(sporkPrivHex)
    const sporkPubBytes = secp256k1.getPublicKey(sporkPrivBytes, true)
    const sporkPubHex = bytesToHex(sporkPubBytes)
    const sporkPkh = hash160Bytes(sporkPubBytes)

    // P2PKH subscript: OP_DUP OP_HASH160 <20-byte-pkh> OP_EQUALVERIFY OP_CHECKSIG
    const subScript = new Uint8Array(25)
    subScript[0] = 0x76
    subScript[1] = 0xa9
    subScript[2] = 0x14
    subScript.set(sporkPkh, 3)
    subScript[23] = 0x88
    subScript[24] = 0xac

    // Build an unsigned 1-input, 1-output raw transaction
    const version = hexToBytes('02000000')
    const vinCount = hexToBytes('01')
    const prevTxId = new Uint8Array(32).fill(0xaa)
    const prevVout = hexToBytes('00000000')
    const emptyScript = hexToBytes('00')
    const sequence = hexToBytes('ffffffff')
    const voutCount = hexToBytes('01')
    const amountBytes = hexToBytes('00e1f50500000000') // 1.00000000 COIN
    const outScriptLen = writeCompactSizeBytes(subScript.length)
    const locktime = hexToBytes('00000000')

    const unsignedTx = new Uint8Array([
      ...version,
      ...vinCount,
      ...prevTxId,
      ...prevVout,
      ...emptyScript,
      ...sequence,
      ...voutCount,
      ...amountBytes,
      ...outScriptLen,
      ...subScript,
      ...locktime
    ])

    // Compute SIGHASH_ALL and sign with Spork private key
    const sighash = computeSighashAllBytes(bytesToHex(unsignedTx), 0, subScript)
    const ecdsaSig = secp256k1.sign(sighash, sporkPrivBytes, { lowS: true })
    const derSig = ecdsaSig.toDERRawBytes()
    const sigWithHashType = new Uint8Array(derSig.length + 1)
    sigWithHashType.set(derSig, 0)
    sigWithHashType[derSig.length] = 0x01 // SIGHASH_ALL

    const sigPush = new Uint8Array([
      ...getPushDataPrefixBytes(sigWithHashType.length),
      ...sigWithHashType
    ])
    const pubPush = new Uint8Array([
      ...getPushDataPrefixBytes(sporkPubBytes.length),
      ...sporkPubBytes
    ])
    const scriptSig = new Uint8Array([...sigPush, ...pubPush])
    const scriptSigLen = writeCompactSizeBytes(scriptSig.length)

    const signedTxBytes = new Uint8Array([
      ...version,
      ...vinCount,
      ...prevTxId,
      ...prevVout,
      ...scriptSigLen,
      ...scriptSig,
      ...sequence,
      ...voutCount,
      ...amountBytes,
      ...outScriptLen,
      ...subScript,
      ...locktime
    ])
    const signedTxHex = bytesToHex(signedTxBytes)

    const verified = verifySporkInputSignature(
      signedTxHex,
      0,
      sigWithHashType,
      sporkPubBytes,
      sporkPubHex
    )
    assert.equal(verified.valid, true)

    // Reject malleable high-S ECDSA signature in verifySporkInputSignature
    const highSSig = new secp256k1.Signature(ecdsaSig.r, secp256k1.CURVE.n - ecdsaSig.s)
    const highSDer = highSSig.toDERRawBytes()
    const highSSigWithHashType = new Uint8Array(highSDer.length + 1)
    highSSigWithHashType.set(highSDer, 0)
    highSSigWithHashType[highSDer.length] = 0x01
    assert.equal(
      verifySporkInputSignature(signedTxHex, 0, highSSigWithHashType, sporkPubBytes, sporkPubHex).valid,
      false
    )

    // Strict scriptSig parser rejects non-push opcodes, non-minimal OP_PUSHDATA1, and trailing bytes
    const strictOk = extractScriptSigPushesStrict(bytesToHex(scriptSig))
    assert.equal(strictOk.valid, true)
    assert.equal(strictOk.pushes.length, 2)
    assert.equal(extractScriptSigPushesStrict(bytesToHex(scriptSig) + '61').valid, false) // trailing OP_NOP
    assert.equal(extractScriptSigPushesStrict('4c01aa').valid, false) // non-minimal OP_PUSHDATA1 (1 byte)
    assert.deepEqual(extractInputOutpoints(signedTxHex), ['aa'.repeat(32) + ':0'])

    // Verify against a different Spork public key -> must fail
    const otherPubBytes = secp256k1.getPublicKey(hexToBytes('44'.repeat(32)), true)
    const wrongVerify = verifySporkInputSignature(
      signedTxHex,
      0,
      sigWithHashType,
      sporkPubBytes,
      bytesToHex(otherPubBytes)
    )
    assert.equal(wrongVerify.valid, false)

    // Test Hybrid CBLSSignedData creation, individual verification & 3-of-5 aggregation
    const wif1 = createTestWif(0x51, true, 0x80)
    const wif2 = createTestWif(0x52, true, 0x80)
    const wif3 = createTestWif(0x53, true, 0x80)
    const mn1 = derivePubKeysFromWIF(wif1)
    const mn2 = derivePubKeysFromWIF(wif2)
    const mn3 = derivePubKeysFromWIF(wif3)
    const txHash = calculateTxHash(signedTxHex)

    const sig1 = createHybridBLSSignedData(mn1.privKeyHex, txHash)
    const sig2 = createHybridBLSSignedData(mn2.privKeyHex, txHash)
    const sig3 = createHybridBLSSignedData(mn3.privKeyHex, txHash)

    assert.equal(
      verifyAndParseBLSSignedData(sig1.signedDataHex, txHash, mn1.compressedPubKey).valid,
      true
    )
    assert.equal(
      verifyAndParseBLSSignedData(sig2.signedDataHex, txHash, mn2.compressedPubKey).valid,
      true
    )
    assert.equal(
      verifyAndParseBLSSignedData(sig3.signedDataHex, txHash, mn3.compressedPubKey).valid,
      true
    )

    const aggResult = verifyAggregatedBLSSignatures(txHash, [
      { pubkey: mn1.compressedPubKey, signature: sig1.signedDataHex },
      { pubkey: mn2.compressedPubKey, signature: sig2.signedDataHex },
      { pubkey: mn3.compressedPubKey, signature: sig3.signedDataHex }
    ])
    assert.equal(aggResult.valid, true)

    const serializedQuorumPayload = serializeQuorumSignatureBytes(txHash, [
      { txhash: '11'.repeat(32), outidx: 0, signature: sig1.signedDataHex },
      { txhash: '22'.repeat(32), outidx: 1, signature: sig2.signedDataHex },
      { txhash: '33'.repeat(32), outidx: 0, signature: sig3.signedDataHex }
    ])
    const qsigPush = new Uint8Array([
      ...getPushDataPrefixBytes(serializedQuorumPayload.length),
      ...serializedQuorumPayload
    ])
    const injectedTx = injectQuorumSigIntoRawTxBytes(signedTxHex, qsigPush)
    assert.ok(injectedTx.length > signedTxBytes.length)

    // Extract pushes from injected vin[0] scriptSig -> should have 3 pushes (sig, pubkey, quorumPayload)
    const { value: inCount, size: inCountVar } = readCompactSizeBytes(injectedTx, 4)
    assert.equal(inCount, 1)
    const scriptLenOffset = 4 + inCountVar + 36
    const { value: newScriptLen, size: newScriptLenVar } = readCompactSizeBytes(
      injectedTx,
      scriptLenOffset
    )
    const newScriptSig = injectedTx.slice(
      scriptLenOffset + newScriptLenVar,
      scriptLenOffset + newScriptLenVar + newScriptLen
    )
    const pushes = extractScriptSigPushesBytes(bytesToHex(newScriptSig))
    assert.equal(pushes.length, 3)
    assert.deepEqual(pushes[2], serializedQuorumPayload)
  })

  it('supports KTDIP3 pure operator-only BLS signing (145B / 290-hex) & rejects duplicate BLS operators or wrong keys', () => {
    const opSecret1 = '11'.repeat(32)
    const opSecret2 = '22'.repeat(32)
    const op1 = deriveBlsPubKeyFromSecret(opSecret1)
    const op2 = deriveBlsPubKeyFromSecret(opSecret2)
    assert.equal(op1.blsPubKeyHex.length, 96)
    assert.equal(op2.blsPubKeyHex.length, 96)

    const txHash = 'ab'.repeat(32)
    const sig1 = createOperatorBLSSignedData(op1.blsSecretHex, txHash)
    const sig2 = createOperatorBLSSignedData(op2.blsSecretHex, txHash)
    assert.equal(sig1.signedDataHex.length, 290)
    assert.equal(sig1.signedDataHex.slice(-2), '00')

    // Passes when matching registered operator BLS pubkey (even if primary pubkey is 33B secp256k1 owner key)
    const ownerPk = '02' + 'aa'.repeat(32)
    const ok = verifyAndParseBLSSignedData(sig1.signedDataHex, txHash, ownerPk, op1.blsPubKeyHex)
    assert.equal(ok.valid, true)
    assert.equal(ok.mode, 'dip3-operator')

    // Rejects mismatched operator pubkey or missing operator pubkey
    assert.equal(
      verifyAndParseBLSSignedData(sig1.signedDataHex, txHash, ownerPk, op2.blsPubKeyHex).valid,
      false
    )
    assert.equal(verifyAndParseBLSSignedData(sig1.signedDataHex, txHash, ownerPk).valid, false)

    // Aggregation succeeds for distinct operators and rejects duplicate operator key
    assert.equal(
      verifyAggregatedBLSSignatures(txHash, [
        { pubkey: ownerPk, operatorPubKey: op1.blsPubKeyHex, signature: sig1.signedDataHex },
        { pubkey: ownerPk, operatorPubKey: op2.blsPubKeyHex, signature: sig2.signedDataHex }
      ]).valid,
      true
    )
    assert.equal(
      verifyAggregatedBLSSignatures(txHash, [
        { pubkey: ownerPk, operatorPubKey: op1.blsPubKeyHex, signature: sig1.signedDataHex },
        { pubkey: ownerPk, operatorPubKey: op1.blsPubKeyHex, signature: sig1.signedDataHex }
      ]).valid,
      false
    )

    // Core DeriveBLSFromCKey (blst_keygen HKDF) derives deterministic KTDIP3 operator BLS key from ECDSA privkey
    const mnWif = createTestWif(0x61, true, 0x80)
    const mnKeys = derivePubKeysFromWIF(mnWif)
    const derivedOp = deriveDip3BlsKeyFromEcdsaPrivKey(mnKeys.privKeyHex)
    assert.equal(derivedOp.blsSecretHex.length, 64)
    assert.equal(derivedOp.blsPubKeyHex.length, 96)
    assert.equal(deriveDip3BlsKeyFromEcdsaPrivKey(mnKeys.privKeyHex).blsPubKeyHex, derivedOp.blsPubKeyHex)

    // Operator BLS signature using derived KTDIP3 key passes verification against registered operatorPubKey
    const derivedOpSig = createOperatorBLSSignedData(derivedOp.blsSecretHex, txHash)
    assert.equal(derivedOpSig.blsPubKeyHex, derivedOp.blsPubKeyHex)
    const derivedCheck = verifyAndParseBLSSignedData(
      derivedOpSig.signedDataHex,
      txHash,
      mnKeys.compressedPubKey,
      derivedOp.blsPubKeyHex
    )
    assert.equal(derivedCheck.valid, true)
    assert.equal(derivedCheck.mode, 'dip3-operator')

    // Hybrid ephemeral-BLS signature passes for legacy non-DIP3 member, but MUST be rejected for KTDIP3 member with registered operatorPubKey
    const hybridSig = createHybridBLSSignedData(mnKeys.privKeyHex, txHash)
    assert.equal(
      verifyAndParseBLSSignedData(hybridSig.signedDataHex, txHash, mnKeys.compressedPubKey).valid,
      true
    )
    assert.equal(
      verifyAndParseBLSSignedData(
        hybridSig.signedDataHex,
        txHash,
        mnKeys.compressedPubKey,
        derivedOp.blsPubKeyHex
      ).valid,
      false
    )
    // Also reject KTDIP3 signatures with trailing ecdsaSig bytes even when memberPubkeyHex is 96-hex BLS
    assert.equal(
      verifyAndParseBLSSignedData(
        hybridSig.signedDataHex,
        txHash,
        derivedOp.blsPubKeyHex,
        derivedOp.blsPubKeyHex
      ).valid,
      false
    )
    const bloatedOpSig = sig1.signedDataHex.slice(0, -2) + '01aa'
    assert.equal(
      verifyAndParseBLSSignedData(bloatedOpSig, txHash, op1.blsPubKeyHex, op1.blsPubKeyHex).valid,
      false
    )
  })

  it('validates 4-char Regtest Bech32m Taproot addresses (ktrt1p...)', () => {
    const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    const polymod = (vals: number[]) => {
      let chk = 1
      for (const v of vals) {
        const b = chk >>> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i]!
      }
      return chk
    }
    const hrp = 'ktrt'
    const hrpExp = [...[...hrp].map((c) => c.charCodeAt(0) >>> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)]
    // witness v1 + 52 zero 5-bit words (valid length 53 data words before 6 checksum words = 59 chars)
    const data = [1, ...new Array(52).fill(0)]
    const enc = polymod([...hrpExp, ...data, 0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3
    const checksum = Array.from({ length: 6 }, (_, i) => (enc >>> (5 * (5 - i))) & 31)
    const ktrtAddr = hrp + '1' + [...data, ...checksum].map((v) => BECH32_CHARSET[v]).join('')
    assert.equal(ktrtAddr.length, 64)
    assert.equal(isValidKristaAddress(ktrtAddr, 'regtest'), true)
    assert.equal(isValidKristaAddress(ktrtAddr, 'main'), false)
    // Flip last char -> bad checksum
    const badAddr = ktrtAddr.slice(0, -1) + (ktrtAddr.endsWith('q') ? 'p' : 'q')
    assert.equal(isValidKristaAddress(badAddr, 'regtest'), false)
  })
})
