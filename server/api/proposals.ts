import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import elliptic from 'elliptic'

const ec = new elliptic.ec('secp256k1')

const RPC_URL = 'http://127.0.0.1:27979'
const RPC_AUTH = Buffer.from('kristarpc:kristarpcpass').toString('base64')
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

      const proposals = readProposals()
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

      // Verify the signature on txHash using pubkey
      try {
        const pubkeyHex = pubkey
        const msgHash = proposal.txHash
        const key = ec.keyFromPublic(pubkeyHex, 'hex')
        
        // elliptic verify expects message as array or hex
        const isValid = key.verify(msgHash, signature)
        if (!isValid) {
          return { success: false, error: 'Invalid ECDSA signature' }
        }
      } catch (err: any) {
        return { success: false, error: `Signature verification failed: ${err.message}` }
      }

      // Save the signature
      proposal.signatures.push({
        txhash,
        outidx,
        pubkey,
        signature
      })

      // Check threshold
      const blockChainInfo = await callRpc('getblockchaininfo')
      const chain = blockChainInfo.chain
      const threshold = (chain === 'regtest' || chain === 'test') ? 2 : 4 // 4 out of 5 for mainnet

      if (proposal.signatures.length >= threshold) {
        // Aggregate quorum signature
        const qsigBuf = serializeQuorumSignature(proposal.txHash, proposal.signatures)
        const qsigPush = Buffer.concat([
          getPushDataPrefix(qsigBuf.length),
          qsigBuf
        ])

        // Parse and rebuild transaction
        const txBuf = Buffer.from(proposal.rawTxHex, 'hex')
        
        // Prefix is 41 bytes (version:4, inputs count:1, outpoint hash:32, outpoint index:4)
        const prefix = txBuf.subarray(0, 41)
        
        // Read scriptSig length
        const scriptSigLenInfo = readCompactSize(txBuf, 41)
        const originalScriptSig = txBuf.subarray(41 + scriptSigLenInfo.size, 41 + scriptSigLenInfo.size + scriptSigLenInfo.value)
        
        // Suffix starts after originalScriptSig
        const suffix = txBuf.subarray(41 + scriptSigLenInfo.size + scriptSigLenInfo.value)

        // New scriptSig: original + push(qsig)
        const newScriptSig = Buffer.concat([originalScriptSig, qsigPush])

        // Final serialized transaction
        const finalTxBuf = Buffer.concat([
          prefix,
          writeCompactSize(newScriptSig.length),
          newScriptSig,
          suffix
        ])

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
