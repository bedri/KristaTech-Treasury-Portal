import crypto from 'node:crypto'
import { defineEventHandler, setResponseStatus } from 'h3'
import {
  callKristaRpc,
  checkApiRateLimit,
  resolveClientIp,
  sanitizeRpcErrorMessage
} from '../utils/security'
import {
  CHAIN_DEFAULTS,
  CORE_VERSION,
  PROTOCOL_VERSION,
  getQuorumMajorityThreshold,
  getTargetQuorumSize,
  maskIpAddress,
  writeCompactSizeBytes
} from '../utils/treasuryCrypto'

const callRpc = callKristaRpc

function doubleSha256(buf: Buffer): Buffer {
  const h1 = crypto.createHash('sha256').update(buf).digest()
  return crypto.createHash('sha256').update(h1).digest()
}

// Bounded cache for seeds: height (number) -> seed (Buffer)
const MAX_SEED_CACHE_ENTRIES = 2000
const seedCache = new Map<number, Buffer>()

function setSeedCacheBounded(height: number, seed: Buffer) {
  if (seedCache.size >= MAX_SEED_CACHE_ENTRIES && !seedCache.has(height)) {
    const oldestKey = seedCache.keys().next().value
    if (oldestKey !== undefined && oldestKey !== 199) {
      seedCache.delete(oldestKey)
    }
  }
  seedCache.set(height, seed)
}

async function getAdamSeed(height: number): Promise<Buffer> {
  const safeHeight = Math.max(0, Math.floor(height))

  // If height < 200, ADAM is not active, return the block hash of that height as seed
  if (safeHeight < 200) {
    const blockHash = await callRpc('getblockhash', [safeHeight])
    return Buffer.from(blockHash, 'hex').reverse()
  }

  // Check if seed is already cached
  if (seedCache.has(safeHeight)) {
    return seedCache.get(safeHeight)!
  }

  // Find the highest cached height less than target height
  let startHeight = 199
  let currentSeed = Buffer.alloc(0)

  // Initialize block 199 seed if not cached
  if (!seedCache.has(199)) {
    const blockHash199 = await callRpc('getblockhash', [199])
    const seed199 = Buffer.from(blockHash199, 'hex').reverse()
    setSeedCacheBounded(199, seed199)
  }

  for (let h = safeHeight; h >= 199; h--) {
    if (seedCache.has(h)) {
      startHeight = h
      currentSeed = seedCache.get(h)!
      break
    }
  }

  // Calculate up to target height
  for (let h = startHeight + 1; h <= safeHeight; h++) {
    const blockHash = await callRpc('getblockhash', [h])
    const block = await callRpc('getblock', [blockHash])
    const vrfProofHex = block.vAdamVRFProof || ''
    const vrfProofBytes = Buffer.from(vrfProofHex, 'hex')

    // Match ComputeNextAdamSeed in src/adam.cpp:
    // If vAdamVRFProof contains a valid CBLSSignedData (>= 144 bytes: 48B blsPubKey + 96B blsSig),
    // hash currentSeed + raw 144 bytes without CompactSize or trailing ECDSA auth signature.
    const dataToHash =
      vrfProofBytes.length >= 144
        ? Buffer.concat([currentSeed, vrfProofBytes.subarray(0, 144)])
        : Buffer.concat([
            currentSeed,
            Buffer.from(writeCompactSizeBytes(vrfProofBytes.length)),
            vrfProofBytes
          ])
    currentSeed = doubleSha256(dataToHash)
    setSeedCacheBounded(h, currentSeed)
  }

  return currentSeed
}

export default defineEventHandler(async (event) => {
  const clientIp = resolveClientIp(event)
  const rateCheck = checkApiRateLimit('quorum-get', clientIp, 60, 60_000)
  if (!rateCheck.allowed) {
    setResponseStatus(event, 429)
    return {
      success: false,
      error: `Rate limit exceeded. Try again in ${rateCheck.retryAfterSec}s.`
    }
  }

  try {
    // Query live blockchain state and live registered Masternode list directly from kristatechd
    const [blockChainInfo, rawMns] = await Promise.all([
      callRpc('getblockchaininfo'),
      callRpc('listmasternodes')
    ])

    const currentHeight = Number(blockChainInfo.blocks)
    const targetHeight = currentHeight + 1 // CheckInputs & ConnectBlock verify at nSpendHeight = H + 1
    const chain = String(blockChainInfo.chain || 'main')
    const defaults = CHAIN_DEFAULTS[chain] || CHAIN_DEFAULTS.main!
    const upgrades =
      blockChainInfo && typeof blockChainInfo.upgrades === 'object' && blockChainInfo.upgrades
        ? blockChainInfo.upgrades
        : {}

    // Filter live on-chain Masternodes from listmasternodes (never fabricate synthetic MNs from PoW miners)
    const allMns = Array.isArray(rawMns) ? rawMns : []
    const enabledMns = allMns.filter(
      (mn: any) => mn.status === 'ENABLED' || mn.status === 'ACTIVE'
    )
    const dip3MasternodeCount = enabledMns.filter((mn: any) =>
      Boolean(mn.dip3 || mn.proTxHash || /^[0-9a-fA-F]{96}$/.test(String(mn.pubkey || '').trim()))
    ).length
    const poseBannedCount = allMns.filter((mn: any) => mn.status === 'POSE_BANNED').length

    const liveMnByOutpoint = new Map<string, any>()
    for (const mn of enabledMns) {
      const key = `${String(mn.txhash || '').toLowerCase()}:${Number(mn.outidx)}`
      liveMnByOutpoint.set(key, mn)
    }

    // Dynamic LLMQ Quorum Scaling (5 -> 9 -> 11 -> 15 in src/llmq.cpp:GetTargetQuorumSize)
    const targetQuorumSize = getTargetQuorumSize(enabledMns.length)

    // Compute live DKG height & Seed height from actual mined blocks on the chain
    let fRotationActive = false
    if (chain === 'main') {
      fRotationActive = targetHeight >= 1400
    } else if (chain === 'test') {
      fRotationActive = targetHeight >= 1000
    } else {
      fRotationActive = targetHeight >= 800
    }

    const dkgInterval = chain === 'regtest' || chain === 'test' ? 10 : 100
    const epochHeight = Math.floor(targetHeight / dkgInterval) * dkgInterval
    let dkgHeight = fRotationActive ? targetHeight : epochHeight
    let seedHeight = Math.min(currentHeight, Math.max(0, epochHeight - 1))

    const seedBuffer = await getAdamSeed(seedHeight)
    let seedHex = Buffer.from(seedBuffer).reverse().toString('hex')

    let developerFundAddress = defaults.devFundAddr
    let sporkPubKey = defaults.sporkPubKey
    let quorumHash: string | undefined

    // Optionally enrich metadata from getactivequorum while strictly verifying members against live listmasternodes
    let activeQuorum: any = null
    try {
      activeQuorum = await callRpc('getactivequorum', [targetHeight])
      if (activeQuorum) {
        if (activeQuorum.developerFundAddress) {
          developerFundAddress = String(activeQuorum.developerFundAddress)
        }
        if (activeQuorum.sporkPubKey) {
          sporkPubKey = String(activeQuorum.sporkPubKey)
        }
        if (
          typeof activeQuorum.quorumHash === 'string' &&
          !/^0+$/.test(activeQuorum.quorumHash)
        ) {
          quorumHash = activeQuorum.quorumHash
        }
        // Only adopt getactivequorum's dkgHeight/seedHeight/seed if seedHeight is an already-mined block
        // and the seed is non-zero (when height < nLLMQActivationHeight, getactivequorum returns future block #1999 & 0000... seed)
        if (
          typeof activeQuorum.seedHeight === 'number' &&
          activeQuorum.seedHeight <= currentHeight &&
          typeof activeQuorum.seed === 'string' &&
          activeQuorum.seed.length === 64 &&
          !/^0+$/.test(activeQuorum.seed)
        ) {
          dkgHeight = Number(activeQuorum.dkgHeight ?? dkgHeight)
          seedHeight = Number(activeQuorum.seedHeight)
          seedHex = activeQuorum.seed
        }
      }
    } catch {
      // Older daemon without getactivequorum or temporary error; live values computed above are used
    }

    // Build Active Quorum Members strictly from live active Masternodes (enabledMns)
    let selectedMns: any[] = []

    if (enabledMns.length > 0) {
      // First check if getactivequorum returned real Masternodes present in listmasternodes
      const verifiedFromRpc: any[] = []
      const seenKeys = new Set<string>()

      if (Array.isArray(activeQuorum?.members)) {
        for (const m of activeQuorum.members) {
          const key = `${String(m.txhash || '').toLowerCase()}:${Number(m.outidx)}`
          const liveMn = liveMnByOutpoint.get(key)
          if (liveMn && !seenKeys.has(key)) {
            seenKeys.add(key)
            const livePk = String(liveMn.pubkey || '').trim()
            const memberPk = String(m.pubkey || '').trim()
            const explicitOpPk = String(m.operatorPubKey || m.blsPubKey || '').trim()
            const operatorPubKey =
              (/^[0-9a-fA-F]{96}$/.test(explicitOpPk) ? explicitOpPk : '') ||
              (/^[0-9a-fA-F]{96}$/.test(livePk) ? livePk : '') ||
              (/^[0-9a-fA-F]{96}$/.test(memberPk) ? memberPk : '')
            const pubkey =
              (/^[0-9a-fA-F]{66,130}$/.test(memberPk) && memberPk.length !== 96
                ? memberPk
                : '') ||
              livePk ||
              memberPk
            verifiedFromRpc.push({
              ...liveMn,
              ...m,
              pubkey,
              operatorPubKey: operatorPubKey || undefined,
              proTxHash: liveMn.proTxHash || m.proTxHash || undefined,
              registeredHeight: liveMn.registeredHeight,
              dip3: Boolean(liveMn.proTxHash || m.proTxHash || operatorPubKey),
              ip: liveMn.ip || m.ip,
              addr: liveMn.addr || m.addr,
              status: liveMn.status || 'ENABLED'
            })
          }
        }
      }

      if (verifiedFromRpc.length > 0 && Array.isArray(activeQuorum?.members)) {
        selectedMns = verifiedFromRpc.slice(0, targetQuorumSize)
      } else {
        // Compute deterministic VRF/ADAM score for each live active Masternode
        const scoredMns = enabledMns.map((mn: any) => {
          const txhashBytes = Buffer.from(String(mn.txhash), 'hex').reverse()
          const outidxBytes = Buffer.alloc(4)
          outidxBytes.writeUInt32LE(parseInt(String(mn.outidx), 10) >>> 0, 0)

          const data = Buffer.concat([seedBuffer, txhashBytes, outidxBytes])
          const score = doubleSha256(data).reverse().toString('hex')

          const livePk = String(mn.pubkey || '').trim()
          const operatorPubKey = /^[0-9a-fA-F]{96}$/.test(livePk) ? livePk : undefined
          return {
            score,
            mn: {
              ...mn,
              operatorPubKey,
              dip3: Boolean(mn.proTxHash || operatorPubKey)
            }
          }
        })

        scoredMns.sort((a: any, b: any) => a.score.localeCompare(b.score))
        // KTDIP3 deduplication by unique BLS operator pubkey in offline fallback
        const deduped: any[] = []
        const seenOps = new Set<string>()
        for (const item of scoredMns) {
          const opKey = String(item.mn.operatorPubKey || '').toLowerCase()
          if (opKey && seenOps.has(opKey)) continue
          if (opKey) seenOps.add(opKey)
          deduped.push(item.mn)
          if (deduped.length >= targetQuorumSize) break
        }
        selectedMns = deduped
      }
    }

    // Mask IP addresses to prevent DDoS/DoS harvesting and assign canonical rank
    const quorumMembers = selectedMns.map((mn: any, idx: number) => ({
      ...mn,
      rank: idx + 1,
      ip: maskIpAddress(mn.ip)
    }))

    const treasuryGovernanceStartHeight = Number(
      activeQuorum?.treasuryGovernanceStartHeight ??
        upgrades['Treasury Governance']?.activationheight ??
        defaults.treasuryGovernanceStartHeight
    )
    const treasuryGovernanceActive = targetHeight >= treasuryGovernanceStartHeight
    const dip3Active = upgrades.DIP3
      ? upgrades.DIP3.status === 'active'
      : upgrades['KTDIP3 v2']
        ? upgrades['KTDIP3 v2'].status === 'active'
        : targetHeight >= 1
    const fairnessActive = upgrades.Fairness
      ? upgrades.Fairness.status === 'active'
      : targetHeight >= 1

    return {
      success: true,
      coreVersion: CORE_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      chain,
      currentHeight,
      targetHeight,
      dkgHeight,
      quorumHash,
      seedHeight,
      seed: seedHex,
      developerFundAddress,
      sporkPubKey,
      treasuryGovernanceStartHeight,
      treasuryGovernanceActive,
      dip3Active,
      fairnessActive,
      activeMasternodeCount: enabledMns.length,
      dip3MasternodeCount,
      poseBannedCount,
      totalMasternodeCount: allMns.length,
      targetQuorumSize,
      threshold: Number(
        activeQuorum?.threshold || getQuorumMajorityThreshold(quorumMembers.length || targetQuorumSize)
      ),
      members: quorumMembers
    }
  } catch (error: any) {
    return {
      success: false,
      coreVersion: CORE_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      error: sanitizeRpcErrorMessage(error, 'Unable to reach KristaTech RPC node')
    }
  }
})
