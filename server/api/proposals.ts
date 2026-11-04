import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import elliptic from 'elliptic'
import { bls12_381 } from '@noble/curves/bls12-381'

const ec = new elliptic.ec('secp256k1')
const BLS_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'

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
      if (typeof rawTxHex !== 'string' || rawTxHex.length > 200000 || !/^[0-9a-fA-F]+$/.test(rawTxHex) ||
          typeof txHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txHash)) {
        return { success: false, error: 'Invalid rawTxHex or txHash format/size' }
      }

      const proposals = readProposals()
      const pendingCount = proposals.filter((p: any) => p.status === 'pending').length
      if (pendingCount >= 50) {
        return { success: false, error: 'Maximum pending proposals limit (50) reached' }
      }
      const newProposal = {
        id: crypto.randomUUID(),
        rawTxHex,
        txHash,
        targetAddress,
        amount,
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
      if (!proposalId || !txhash || !pubkey || !signature) {
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

      // Check if already signed by this masternode
      const alreadySigned = proposal.signatures.some((s: any) => s.txhash === txhash && s.outidx === outidx)
      if (alreadySigned) {
        return { success: false, error: 'Already signed by this masternode' }
      }

      // Verify hybrid BLS12-381 + secp256k1 signature (CBLSSignedData) matching src/llmq.cpp:Verify
      const verifyResult = verifyAndParseBLSSignedData(signature, proposal.txHash, pubkey)
      if (!verifyResult.valid) {
        return { success: false, error: verifyResult.error || 'Invalid hybrid BLS12-381 + ECDSA signature' }
      }

      // Save the signature
      proposal.signatures.push({
        txhash,
        outidx: Number(outidx),
        pubkey,
        signature
      })

      // Check threshold
      const blockChainInfo = await callRpc('getblockchaininfo')
      const chain = blockChainInfo.chain
      const threshold = (chain === 'regtest') ? 2 : 3 // 3 out of 5 majority for mainnet/testnet

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
        } catch (broadcastErr: any) {
          proposal.status = 'failed'
          proposal.error = broadcastErr.message
        }
      }

      writeProposals(proposals)
      return { success: true, proposal }
    }
  }

  return { error: 'Method not allowed' }
})
