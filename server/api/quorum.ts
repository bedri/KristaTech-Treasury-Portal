import crypto from 'crypto'

const RPC_URL = 'http://127.0.0.1:27979'
const RPC_AUTH = Buffer.from('kristarpc:kristarpcpass').toString('base64')

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

function doubleSha256(buf: Buffer): Buffer {
  const h1 = crypto.createHash('sha256').update(buf).digest()
  return crypto.createHash('sha256').update(h1).digest()
}

// Global cache for seeds: height (number) -> seed (Buffer)
const seedCache = new Map<number, Buffer>()

async function getAdamSeed(height: number): Promise<Buffer> {
  // If height < 200, ADAM is not active, return the block hash of that height as seed
  if (height < 200) {
    const blockHash = await callRpc('getblockhash', [height])
    return Buffer.from(blockHash, 'hex').reverse()
  }

  // Check if seed is already cached
  if (seedCache.has(height)) {
    return seedCache.get(height)!
  }

  // Find the highest cached height less than target height
  let startHeight = 199
  let currentSeed = Buffer.alloc(0)

  // Initialize block 199 seed if not cached
  if (!seedCache.has(199)) {
    const blockHash199 = await callRpc('getblockhash', [199])
    const seed199 = Buffer.from(blockHash199, 'hex').reverse()
    seedCache.set(199, seed199)
  }

  for (let h = height; h >= 199; h--) {
    if (seedCache.has(h)) {
      startHeight = h
      currentSeed = seedCache.get(h)!
      break
    }
  }

  // Recursively calculate up to target height
  for (let h = startHeight + 1; h <= height; h++) {
    const blockHash = await callRpc('getblockhash', [h])
    const block = await callRpc('getblock', [blockHash])
    const vrfProofHex = block.vAdamVRFProof || ''
    const vrfProofBytes = Buffer.from(vrfProofHex, 'hex')

    // Serialize: currentSeed (32 bytes) + compact size + vrfProofBytes
    const dataToHash = Buffer.concat([
      currentSeed,
      writeCompactSize(vrfProofBytes.length),
      vrfProofBytes
    ])
    currentSeed = doubleSha256(dataToHash)
    seedCache.set(h, currentSeed)
  }

  return currentSeed
}

export default defineEventHandler(async (event) => {
  try {
    const blockChainInfo = await callRpc('getblockchaininfo')
    const currentHeight = blockChainInfo.blocks
    const chain = blockChainInfo.chain

    // Check if Quorum Rotation is active
    let fRotationActive = false
    if (chain === 'main') {
      fRotationActive = (currentHeight >= 3000)
    } else if (chain === 'test') {
      fRotationActive = (currentHeight >= 1000)
    } else { // regtest
      fRotationActive = (currentHeight >= 800)
    }

    // Determine DKG height interval
    const dkgInterval = (chain === 'regtest' || chain === 'test') ? 10 : 100
    
    let dkgHeight = Math.floor(currentHeight / dkgInterval) * dkgInterval
    let seedHeight = dkgHeight - 1

    if (fRotationActive) {
      dkgHeight = currentHeight
      const epochHeight = Math.floor(currentHeight / dkgInterval) * dkgInterval
      seedHeight = epochHeight - 1
    }

    const seedBuffer = await getAdamSeed(seedHeight)
    const seedHex = Buffer.from(seedBuffer).reverse().toString('hex')

    // Get all enabled/active masternodes
    const allMns = await callRpc('listmasternodes')
    const enabledMns = allMns.filter((mn: any) => 
      mn.status === 'ENABLED' || mn.status === 'ACTIVE'
    )

    // Compute score for each masternode
    const scoredMns = enabledMns.map((mn: any) => {
      const txhashBytes = Buffer.from(mn.txhash, 'hex').reverse()
      const outidxBytes = Buffer.alloc(4)
      outidxBytes.writeUInt32LE(parseInt(mn.outidx), 0)

      const data = Buffer.concat([seedBuffer, txhashBytes, outidxBytes])
      const score = doubleSha256(data).reverse().toString('hex')

      return {
        score,
        mn
      }
    })

    // Sort by score ascending (lowest score is ranked highest)
    scoredMns.sort((a: any, b: any) => a.score.localeCompare(b.score))

    // Select members using sliding window or standard behavior
    let selectedMns = []
    if (fRotationActive) {
      const M = scoredMns.length
      if (M >= 5) {
        const offset = currentHeight
        for (let i = 0; i < 5; ++i) {
          selectedMns.push(scoredMns[(offset + i) % M].mn)
        }
      } else {
        selectedMns = scoredMns.map((item: any) => item.mn)
      }
    } else {
      selectedMns = scoredMns.slice(0, 5).map((item: any) => item.mn)
    }

    // Mask their IP addresses to prevent DDoS/DoS harvesting
    const quorumMembers = selectedMns.map((mn: any) => {
      const mnCopy = { ...mn }
      if (mnCopy.ip) {
        const parts = mnCopy.ip.split(':')
        const ipPart = parts[0]
        const portPart = parts[1] ? `:${parts[1]}` : ''
        
        if (ipPart.includes('.')) {
          const octets = ipPart.split('.')
          if (octets.length === 4) {
            mnCopy.ip = `${octets[0]}.xxx.xxx.${octets[3]}${portPart}`
          } else {
            mnCopy.ip = `xxx.xxx.xxx.xxx${portPart}`
          }
        } else {
          // IPv6 or hostname
          mnCopy.ip = `[xxxx:xxxx:xxxx::xxxx]${portPart}`
        }
      }
      return mnCopy
    })

    return {
      success: true,
      currentHeight,
      dkgHeight,
      seedHeight,
      seed: seedHex,
      members: quorumMembers
    }
  } catch (error: any) {
    return {
      success: false,
      error: error.message
    }
  }
})
