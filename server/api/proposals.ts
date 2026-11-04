import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import elliptic from 'elliptic'
import { bls12_381 } from '@noble/curves/bls12-381'

const ec = new elliptic.ec('secp256k1')
const BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'

const CHAIN_DEFAULTS: Record<string, { devFundAddr: string; sporkPubKey: string }> = {
  main: {
    devFundAddr: 'KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP',
    sporkPubKey: '024897ee03b6f8133aa5fc926c8f9fd83b1454a817fda9fc907de18866eba0030a'
  },
  test: {
    devFundAddr: 'ktEooARF3HdV8w59LUc5jaHrS7GBL7974Uy',
    sporkPubKey: '03b4394f924c8bdbea7379fbcde9bf1b5a32d0f04631312b18c4ba3889a89b6a0d'
  },
  regtest: {
    devFundAddr: 'kt5KNitasi4bEHbQQCrpy6445nJD7uSVNux',
    sporkPubKey: '043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7'
  }
}

function pubkeysMatch(pkHexA: string, pkHexB: string): boolean {
  try {
    if (pkHexA.toLowerCase() === pkHexB.toLowerCase()) return true
    const keyA = ec.keyFromPublic(pkHexA, 'hex')
    const keyB = ec.keyFromPublic(pkHexB, 'hex')
    return keyA.getPublic(true, 'hex').toLowerCase() === keyB.getPublic(true, 'hex').toLowerCase()
  } catch {
    return false
  }
}

function extractScriptSigPushes(scriptSigHex: string): Buffer[] {
  const buf = Buffer.from(scriptSigHex, 'hex')
  const pushes: Buffer[] = []
  let i = 0
  while (i < buf.length) {
    const op = buf.readUInt8(i)
    i += 1
    let len = 0
    if (op >= 1 && op <= 75) {
      len = op
    } else if (op === 76) {
      if (i + 1 > buf.length) break
      len = buf.readUInt8(i)
      i += 1
    } else if (op === 77) {
      if (i + 2 > buf.length) break
      len = buf.readUInt16LE(i)
      i += 2
    } else if (op === 78) {
      if (i + 4 > buf.length) break
      len = buf.readUInt32LE(i)
      i += 4
    } else {
      break
    }
    if (i + len > buf.length) break
    pushes.push(buf.subarray(i, i + len))
    i += len
  }
  return pushes
}

async function fetchActiveQuorumForSpend() {
  const blockChainInfo = await callRpc('getblockchaininfo')
  const currentHeight = Number(blockChainInfo.blocks)
  const targetHeight = currentHeight + 1
  const chain = String(blockChainInfo.chain || 'main')
  const defaults = CHAIN_DEFAULTS[chain] || CHAIN_DEFAULTS.main

  const activeQuorum = await callRpc('getactivequorum', [targetHeight])
  return {
    chain,
    currentHeight,
    targetHeight,
    threshold: Number(activeQuorum?.threshold || (chain === 'regtest' ? 2 : 3)),
    developerFundAddress: String(activeQuorum?.developerFundAddress || defaults.devFundAddr),
    sporkPubKey: String(activeQuorum?.sporkPubKey || defaults.sporkPubKey),
    members: Array.isArray(activeQuorum?.members) ? activeQuorum.members : []
  }
}

function doubleSha256(buf: Buffer): Buffer {
  const h1 = crypto.createHash('sha256').update(buf).digest()
  return crypto.createHash('sha256').update(h1).digest()
}

const RPC_URL = process.env.NUXT_RPC_URL || 'http://127.0.0.1:27998'
const RPC_AUTH = Buffer.from(`${process.env.NUXT_RPC_USER || 'kristarpc'}:${process.env.NUXT_RPC_PASSWORD || 'kristapassword'}`).toString('base64')
const DATA_FILE = path.join('/home/bedri/Coin-Projects/KristaTech-Treasury-Portal', 'proposals.json')

async function callRpc(method: string, params: any[] = []) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Basic ${RPC_AUTH}`
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'nuxt-api',
      method,
      params
    })
  })
  if (!response.ok) {
    throw new Error(`RPC call ${method} failed: ${response.statusText}`)
  }
  const json: any = await response.json()
  return json.result
}

// Read/write proposals
function readProposals() {
  if (!fs.existsSync(DATA_FILE)) {
    return []
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'))
  } catch {
    return []
  }
}

function writeProposals(data: any) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8')
}

// Helpers for compact size
function writeCompactSize(size: number): Buffer {
  if (size < 253) {
    return Buffer.from([size])
  } else if (size <= 0xffff) {
    const buf = Buffer.alloc(3)
    buf.writeUInt8(253, 0)
    buf.writeUInt16LE(size, 1)
    return buf
  } else if (size <= 0xffffffff) {
    const buf = Buffer.alloc(5)
    buf.writeUInt8(254, 0)
    buf.writeUInt32LE(size, 1)
    return buf
  } else {
    const buf = Buffer.alloc(9)
    buf.writeUInt8(255, 0)
    buf.writeBigUInt64LE(BigInt(size), 1)
    return buf
  }
}

// Helper to parse compact size from buffer
function readCompactSize(buf: Buffer, offset: number): { value: number; size: number } {
  const first = buf.readUInt8(offset)
  if (first < 253) {
    return { value: first, size: 1 }
  } else if (first === 253) {
    return { value: buf.readUInt16LE(offset + 1), size: 3 }
  } else if (first === 254) {
    return { value: buf.readUInt32LE(offset + 1), size: 5 }
  } else {
    return { value: Number(buf.readBigUInt64LE(offset + 1)), size: 9 }
  }
}

// Helper to push data in Bitcoin Script
function getPushDataPrefix(length: number): Buffer {
  if (length < 76) {
    return Buffer.from([length])
  } else if (length <= 255) {
    return Buffer.from([76, length])
  } else if (length <= 65535) {
    const buf = Buffer.alloc(3)
    buf.writeUInt8(77, 0)
    buf.writeUInt16LE(length, 1)
    return buf
  } else {
    const buf = Buffer.alloc(5)
    buf.writeUInt8(78, 0)
    buf.writeUInt32LE(length, 1)
    return buf
  }
}

// Helper to deserialize and verify CBLSSignedData (blsPubKey[48] + blsSig[96] + compactSize + ecdsaSig)
// matching CQuorumSignature::Verify in src/llmq.cpp:43-108
function verifyAndParseBLSSignedData(
  sigHex: string,
  txHashHex: string,
  memberPubkeyHex: string
): { valid: boolean; error?: string; blsPubKey?: Uint8Array; blsSig?: Uint8Array } {
  try {
    const sigBuf = Buffer.from(sigHex, 'hex')
    // Minimum size: 48 (G1 pubkey) + 96 (G2 sig) + 1 (compactSize) + 64 (ECDSA DER)
    if (sigBuf.length < 209 || sigBuf.length > 512) {
      return { valid: false, error: `Invalid CBLSSignedData byte length (${sigBuf.length}); expected 48B blsPubKey + 96B blsSig + DER ecdsaSig` }
    }

    const blsPubKey = sigBuf.subarray(0, 48)
    const blsSig = sigBuf.subarray(48, 144)
    const ecdsaLenInfo = readCompactSize(sigBuf, 144)
    const expectedTotal = 144 + ecdsaLenInfo.size + ecdsaLenInfo.value
    if (expectedTotal !== sigBuf.length || ecdsaLenInfo.value === 0) {
      return { valid: false, error: 'Malformed CBLSSignedData compactSize for ecdsaSig' }
    }
    const ecdsaSig = sigBuf.subarray(144 + ecdsaLenInfo.size, expectedTotal)

    // 1. Verify ECDSA signature by memberPubKey over Hash(blsPubKey) (double-SHA256)
    const hashPubKey = doubleSha256(blsPubKey)
    const key = ec.keyFromPublic(memberPubkeyHex, 'hex')
    if (!key.verify(hashPubKey, ecdsaSig)) {
      return { valid: false, error: 'Invalid Masternode ECDSA authorization signature over Hash(blsPubKey)' }
    }

    // 2. Verify BLS12-381 signature over blockHash.begin() (32-byte little-endian internal uint256)
    const msgBlockHash = new Uint8Array(Buffer.from(txHashHex, 'hex').reverse())
    const blsOk = bls12_381.verify(new Uint8Array(blsSig), msgBlockHash, new Uint8Array(blsPubKey), { DST: BLS_DST })
    if (!blsOk) {
      return { valid: false, error: 'Invalid BLS12-381 signature over proposal txHash' }
    }

    return {
      valid: true,
      blsPubKey: new Uint8Array(blsPubKey),
      blsSig: new Uint8Array(blsSig)
    }
  } catch (err: any) {
    return { valid: false, error: `CBLSSignedData verification failed: ${err.message}` }
  }
}

// Helper to append quorum signature push to all inputs of a serialized transaction
function injectQuorumSigIntoRawTx(rawTxHex: string, qsigPush: Buffer): Buffer {
  const txBuf = Buffer.from(rawTxHex, 'hex')
  let offset = 0

  // nVersion (4 bytes)
  const version = txBuf.subarray(offset, offset + 4)
  offset += 4

  // vin count
  const vinCountInfo = readCompactSize(txBuf, offset)
  const vinCountBuf = txBuf.subarray(offset, offset + vinCountInfo.size)
  offset += vinCountInfo.size

  const parts: Buffer[] = [version, vinCountBuf]

  for (let i = 0; i < vinCountInfo.value; i++) {
    // prevout (32-byte hash + 4-byte index)
    const prevout = txBuf.subarray(offset, offset + 36)
    offset += 36

    const scriptSigLenInfo = readCompactSize(txBuf, offset)
    offset += scriptSigLenInfo.size
    const originalScriptSig = txBuf.subarray(offset, offset + scriptSigLenInfo.value)
    offset += scriptSigLenInfo.value

    const nSequence = txBuf.subarray(offset, offset + 4)
    offset += 4

    const newScriptSig = Buffer.concat([originalScriptSig, qsigPush])
    parts.push(prevout, writeCompactSize(newScriptSig.length), newScriptSig, nSequence)
  }

  // Remaining bytes (vout + nLockTime)
  parts.push(txBuf.subarray(offset))
  return Buffer.concat(parts)
}

// Helper to aggregate CQuorumSignature
function serializeQuorumSignature(txHashHex: string, sigs: any[]): Buffer {
  const blockHashBuf = Buffer.from(txHashHex, 'hex').reverse()
  const parts = [blockHashBuf]

  // signatures vector size
  parts.push(writeCompactSize(sigs.length))

  for (const item of sigs) {
    const txhashBuf = Buffer.from(item.txhash, 'hex').reverse()
    const outidxBuf = Buffer.alloc(4)
    outidxBuf.writeUInt32LE(item.outidx, 0)
    const sigBuf = Buffer.from(item.signature, 'hex')

    parts.push(txhashBuf)
    parts.push(outidxBuf)
    parts.push(writeCompactSize(sigBuf.length))
    parts.push(sigBuf)
  }

  return Buffer.concat(parts)
}

export default defineEventHandler(async (event) => {
  const method = event.node.req.method

  if (method === 'GET') {
    return readProposals()
  }

  if (method === 'POST') {
    const body = await readBody(event)
    const { action } = body

    if (action === 'create') {
      const { rawTxHex, txHash, targetAddress, amount } = body
      if (!rawTxHex || !txHash || !targetAddress || !amount) {
        return { success: false, error: 'Missing parameters' }
      }
      const cleanRawHex = String(rawTxHex).trim()
      const cleanTxHash = String(txHash).trim().toLowerCase()
      if (cleanRawHex.length === 0 || cleanRawHex.length % 2 !== 0 || cleanRawHex.length > 200000 || !/^[0-9a-fA-F]+$/.test(cleanRawHex) ||
          !/^[0-9a-fA-F]{64}$/.test(cleanTxHash)) {
        return { success: false, error: 'Invalid rawTxHex or txHash format/size' }
      }

      // 1. Verify txHash matches double-SHA256(rawTxHex)
      const computedTxHash = doubleSha256(Buffer.from(cleanRawHex, 'hex')).reverse().toString('hex').toLowerCase()
      if (computedTxHash !== cleanTxHash) {
        return { success: false, error: 'txHash does not match double-SHA256 digest of rawTxHex' }
      }

      // 2. Verify rawTxHex is a valid transaction spending an unspent Developer Fund UTXO signed by Spork Key
      let decodedTx: any
      let quorumInfo: any
      try {
        quorumInfo = await fetchActiveQuorumForSpend()
        decodedTx = await callRpc('decoderawtransaction', [cleanRawHex])
      } catch (err: any) {
        return { success: false, error: `Failed to decode or validate raw transaction: ${err.message}` }
      }

      if (!decodedTx || !Array.isArray(decodedTx.vin) || decodedTx.vin.length === 0 || !Array.isArray(decodedTx.vout) || decodedTx.vout.length === 0) {
        return { success: false, error: 'Decoded transaction has no inputs or outputs' }
      }

      const proposals = readProposals()
      const pendingProposals = proposals.filter((p: any) => p.status === 'pending')
      if (pendingProposals.length >= 50) {
        return { success: false, error: 'Maximum pending proposals limit (50) reached' }
      }
      if (proposals.some((p: any) => String(p.txHash).toLowerCase() === cleanTxHash && p.status !== 'failed')) {
        return { success: false, error: 'Proposal with this txHash already exists' }
      }

      for (const vin of decodedTx.vin) {
        if (!vin.txid || vin.vout === undefined) {
          return { success: false, error: 'Invalid coinbase or missing input outpoint in proposal transaction' }
        }
        // Check UTXO is unspent and belongs to Developer Fund Address
        const txOut = await callRpc('gettxout', [vin.txid, Number(vin.vout), true])
        if (!txOut) {
          return { success: false, error: `Input UTXO ${vin.txid}:${vin.vout} is already spent or does not exist` }
        }
        const outAddresses: string[] = txOut.scriptPubKey?.addresses || []
        if (!outAddresses.includes(quorumInfo.developerFundAddress)) {
          return { success: false, error: `Input UTXO ${vin.txid}:${vin.vout} does not belong to Developer Fund (${quorumInfo.developerFundAddress})` }
        }

        // Check scriptSig contains <sporkSig> <sporkPubKey>
        const pushes = extractScriptSigPushes(vin.scriptSig?.hex || '')
        if (pushes.length < 2) {
          return { success: false, error: 'Input scriptSig must be pre-signed with Spork signature and Spork public key' }
        }
        const pushedPubKeyHex = pushes[1].toString('hex')
        if (!pubkeysMatch(pushedPubKeyHex, quorumInfo.sporkPubKey)) {
          return { success: false, error: 'Input scriptSig public key does not match consensus Spork public key' }
        }
      }

      const newProposal = {
        id: crypto.randomUUID(),
        rawTxHex: cleanRawHex,
        txHash: cleanTxHash,
        targetAddress: String(targetAddress).trim(),
        amount: Number(amount),
        signatures: [],
        status: 'pending',
        createdAt: new Date().toISOString()
      }

      proposals.push(newProposal)
      writeProposals(proposals)

      return { success: true, proposal: newProposal }
    }

    if (action === 'sign') {
      const { proposalId, txhash, outidx, pubkey, signature } = body
      if (!proposalId || !txhash || outidx === undefined || !pubkey || !signature) {
        return { success: false, error: 'Missing parameters' }
      }

      const proposals = readProposals()
      const proposal = proposals.find((p: any) => p.id === proposalId)
      if (!proposal) {
        return { success: false, error: 'Proposal not found' }
      }
      if (proposal.status !== 'pending') {
        return { success: false, error: 'Proposal is not pending' }
      }

      // 1. Fetch active consensus quorum for next block (nSpendHeight = currentHeight + 1)
      let quorumInfo: any
      try {
        quorumInfo = await fetchActiveQuorumForSpend()
      } catch (err: any) {
        return { success: false, error: `Failed to fetch active quorum: ${err.message}` }
      }

      // 2. Verify that (txhash, outidx, pubkey) is an elected member of the active quorum
      const electedMember = quorumInfo.members.find((m: any) =>
        String(m.txhash).toLowerCase() === String(txhash).toLowerCase() &&
        Number(m.outidx) === Number(outidx) &&
        pubkeysMatch(String(m.pubkey), String(pubkey))
      )
      if (!electedMember) {
        return { success: false, error: 'Signer is not an elected member of the active quorum for the next block' }
      }

      // 3. Prune any stale signatures from previous quorum epochs so epoch boundaries never brick the proposal
      proposal.signatures = (proposal.signatures || []).filter((s: any) => {
        const stillInQuorum = quorumInfo.members.find((m: any) =>
          String(m.txhash).toLowerCase() === String(s.txhash).toLowerCase() &&
          Number(m.outidx) === Number(s.outidx) &&
          pubkeysMatch(String(m.pubkey), String(s.pubkey))
        )
        if (!stillInQuorum) return false
        return verifyAndParseBLSSignedData(s.signature, proposal.txHash, stillInQuorum.pubkey).valid
      })

      // 4. Check if already signed by this masternode in the current active quorum
      const alreadySigned = proposal.signatures.some((s: any) =>
        String(s.txhash).toLowerCase() === String(electedMember.txhash).toLowerCase() &&
        Number(s.outidx) === Number(electedMember.outidx)
      )
      if (alreadySigned) {
        return { success: false, error: 'Already signed by this masternode' }
      }

      // 5. Verify hybrid BLS12-381 + secp256k1 signature (CBLSSignedData) against canonical electedMember.pubkey
      const verifyResult = verifyAndParseBLSSignedData(signature, proposal.txHash, electedMember.pubkey)
      if (!verifyResult.valid) {
        return { success: false, error: verifyResult.error || 'Invalid hybrid BLS12-381 + ECDSA signature' }
      }

      // Save the signature using canonical quorum member fields
      proposal.signatures.push({
        txhash: electedMember.txhash,
        outidx: Number(electedMember.outidx),
        pubkey: electedMember.pubkey,
        signature
      })

      const threshold = quorumInfo.threshold

      if (proposal.signatures.length >= threshold) {
        // Verify aggregated BLS12-381 signature across all signing quorum members (matching src/llmq.cpp:101-105)
        try {
          const parsedPks: Uint8Array[] = []
          const parsedSigs: Uint8Array[] = []
          for (const item of proposal.signatures) {
            const p = verifyAndParseBLSSignedData(item.signature, proposal.txHash, item.pubkey)
            if (p.valid && p.blsPubKey && p.blsSig) {
              parsedPks.push(p.blsPubKey)
              parsedSigs.push(p.blsSig)
            }
          }
          const aggPk = bls12_381.aggregatePublicKeys(parsedPks)
          const aggSig = bls12_381.aggregateSignatures(parsedSigs)
          const msgBlockHash = new Uint8Array(Buffer.from(proposal.txHash, 'hex').reverse())
          if (!bls12_381.verify(aggSig, msgBlockHash, aggPk, { DST: BLS_DST })) {
            return { success: false, error: 'Aggregated BLS12-381 quorum signature verification failed' }
          }
        } catch (aggErr: any) {
          return { success: false, error: `BLS aggregation failed: ${aggErr.message}` }
        }

        // Serialize CQuorumSignature and inject into all transaction inputs
        const qsigBuf = serializeQuorumSignature(proposal.txHash, proposal.signatures)
        const qsigPush = Buffer.concat([
          getPushDataPrefix(qsigBuf.length),
          qsigBuf
        ])

        const finalTxBuf = injectQuorumSigIntoRawTx(proposal.rawTxHex, qsigPush)
        const finalTxHex = finalTxBuf.toString('hex')

        try {
          const broadcastResult = await callRpc('sendrawtransaction', [finalTxHex])
          proposal.status = 'broadcasted'
          proposal.finalTxid = broadcastResult
          proposal.finalTxHex = finalTxHex
          delete proposal.error
        } catch (broadcastErr: any) {
          // Do not permanently lock the proposal in 'failed' state if the UTXO is still unspent
          proposal.error = broadcastErr.message
          try {
            const decoded = await callRpc('decoderawtransaction', [proposal.rawTxHex])
            const firstVin = decoded?.vin?.[0]
            const txOut = firstVin ? await callRpc('gettxout', [firstVin.txid, Number(firstVin.vout), true]) : null
            if (!txOut) {
              proposal.status = 'failed'
            }
          } catch {
            // Keep status = 'pending' so quorum members can retry after epoch/sync transition
          }
        }
      }

      writeProposals(proposals)
      return { success: true, proposal }
    }
  }

  return { error: 'Method not allowed' }
})
