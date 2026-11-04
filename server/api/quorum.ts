import crypto from 'crypto'

const RPC_URL = process.env.NUXT_RPC_URL || 'http://127.0.0.1:27998'
const RPC_AUTH = Buffer.from(`${process.env.NUXT_RPC_USER || 'kristarpc'}:${process.env.NUXT_RPC_PASSWORD || 'kristapassword'}`).toString('base64')

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

function maskIpAddress(ip: string | undefined): string {
  if (!ip) return 'On-Chain MN'
  if (ip === 'On-Chain MN' || ip.startsWith('ADAM-Miner')) return ip
  const parts = ip.split(':')
  const ipPart = parts[0] || ''
  const portPart = parts[1] ? `:${parts[1]}` : ''

  if (ipPart.includes('.')) {
    const octets = ipPart.split('.')
    if (octets.length === 4) {
      return `${octets[0]}.xxx.xxx.${octets[3]}${portPart}`
    }
    return `xxx.xxx.xxx.xxx${portPart}`
  }
  return `[xxxx:xxxx:xxxx::xxxx]${portPart}`
}

export default defineEventHandler(async (event) => {
  try {
    const blockChainInfo = await callRpc('getblockchaininfo')
    const currentHeight = blockChainInfo.blocks
    const targetHeight = currentHeight + 1 // CheckInputs & ConnectBlock verify at nSpendHeight = H + 1
    const chain = blockChainInfo.chain

    // Prefer consensus-direct getactivequorum RPC from kristatechd at targetHeight = currentHeight + 1 (SEC-12 compliant)
    try {
      const activeQuorum = await callRpc('getactivequorum', [targetHeight])
      if (activeQuorum && Array.isArray(activeQuorum.members)) {
        const maskedMembers = activeQuorum.members.map((mn: any) => ({
          ...mn,
          ip: maskIpAddress(mn.ip)
        }))
        return {
          success: true,
          chain: activeQuorum.chain,
          currentHeight: activeQuorum.currentHeight,
          targetHeight: activeQuorum.targetHeight ?? targetHeight,
          dkgHeight: activeQuorum.dkgHeight,
          seedHeight: activeQuorum.seedHeight,
          seed: activeQuorum.seed,
          threshold: activeQuorum.threshold || ((maskedMembers.length < 5) ? 2 : 3),
          members: maskedMembers
        }
      }
    } catch {
      // Fallback to manual RPC composition if connected to an older daemon without getactivequorum
    }

    // Check if Quorum Rotation is active at targetHeight (H + 1)
    let fRotationActive = false
    if (chain === 'main') {
      fRotationActive = (targetHeight >= 1400)
    } else if (chain === 'test') {
      fRotationActive = (targetHeight >= 1000)
    } else { // regtest
      fRotationActive = (targetHeight >= 800)
    }

    // Determine DKG height interval
    const dkgInterval = (chain === 'regtest' || chain === 'test') ? 10 : 100
    
    let dkgHeight = Math.floor(targetHeight / dkgInterval) * dkgInterval
    let seedHeight = dkgHeight - 1

    if (fRotationActive) {
      dkgHeight = targetHeight
      const epochHeight = Math.floor(targetHeight / dkgInterval) * dkgInterval
      seedHeight = epochHeight - 1
    }

    const seedBuffer = await getAdamSeed(seedHeight)
    const seedHex = Buffer.from(seedBuffer).reverse().toString('hex')

    // Get all enabled/active masternodes
    const allMns = await callRpc('listmasternodes')
    let enabledMns = (Array.isArray(allMns) ? allMns : []).filter((mn: any) => 
      mn.status === 'ENABLED' || mn.status === 'ACTIVE'
    )

    // SEC-12 fallback: when < 5 active masternodes exist, ElectQuorumMembers falls back to GetAdamMinerPool(nHeight - 1)
    if (enabledMns.length < 5) {
      const adamMiners = await callRpc('getadamminers', [Math.max(0, dkgHeight - 1)]).catch(() => [])
      const pool: string[] = Array.isArray(adamMiners?.pool) ? adamMiners.pool : (Array.isArray(adamMiners) ? adamMiners : [])
      if (pool.length > 0) {
        enabledMns = pool.map((pubkeyHex: string, idx: number) => {
          const pubkeyBytes = Buffer.from(pubkeyHex, 'hex')
          const pseudoTxHash = doubleSha256(pubkeyBytes).reverse().toString('hex')
          return {
            rank: idx + 1,
            txhash: pseudoTxHash,
            outidx: idx,
            pubkey: pubkeyHex,
            status: 'ENABLED',
            ip: `ADAM-Miner #${idx + 1}`
          }
        })
      }
    }

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

    // Select top 5 members (standard DKG behavior matching src/llmq.cpp:ElectQuorumMembers)
    const selectedMns = scoredMns.slice(0, 5).map((item: any) => item.mn)

    // Mask their IP addresses to prevent DDoS/DoS harvesting
    const quorumMembers = selectedMns.map((mn: any) => ({
      ...mn,
      ip: maskIpAddress(mn.ip)
    }))

    return {
      success: true,
      chain,
      currentHeight,
      targetHeight,
      dkgHeight,
      seedHeight,
      seed: seedHex,
      threshold: (quorumMembers.length < 5) ? 2 : 3,
      members: quorumMembers
    }
  } catch (error: any) {
    return {
      success: false,
      error: error.message
    }
  }
})
