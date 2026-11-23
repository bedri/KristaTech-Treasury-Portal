import crypto from 'node:crypto'
import { defineEventHandler, readBody, setResponseStatus } from 'h3'
import {
  acquireProposalLock,
  callKristaRpc,
  checkApiRateLimit,
  readProposalsAtomically,
  resolveClientIp,
  sanitizeRpcErrorMessage,
  writeProposalsAtomically
} from '../utils/security'
import {
  CHAIN_DEFAULTS,
  blsPubKeysMatch,
  bytesToHex,
  calculateTxHash,
  concatBytes,
  extractScriptSigPushesBytes,
  getPushDataPrefixBytes,
  getQuorumMajorityThreshold,
  injectQuorumSigIntoRawTxBytes,
  isValidKristaAddress,
  normalizeTaprootAddress,
  pubkeysMatch,
  serializeQuorumSignatureBytes,
  verifyAggregatedBLSSignatures,
  verifyAndParseBLSSignedData,
  verifySporkInputSignature
} from '../utils/treasuryCrypto'

const callRpc = callKristaRpc

async function fetchActiveQuorumForSpend() {
  const [blockChainInfo, rawMns] = await Promise.all([
    callRpc('getblockchaininfo'),
    callRpc('listmasternodes').catch(() => [])
  ])
  const currentHeight = Number(blockChainInfo.blocks)
  const targetHeight = currentHeight + 1
  const chain = String(blockChainInfo.chain || 'main')
  const defaults = CHAIN_DEFAULTS[chain] || CHAIN_DEFAULTS.main!

  const enabledMns = (Array.isArray(rawMns) ? rawMns : []).filter(
    (mn: any) => mn.status === 'ENABLED' || mn.status === 'ACTIVE'
  )
  const liveMnMap = new Map<string, any>()
  for (const mn of enabledMns) {
    liveMnMap.set(`${String(mn.txhash || '').toLowerCase()}:${Number(mn.outidx)}`, mn)
  }

  const activeQuorum = await callRpc('getactivequorum', [targetHeight]).catch(() => null)
  const rawMembers = Array.isArray(activeQuorum?.members) ? activeQuorum.members : []
  const members: any[] = []
  for (const m of rawMembers) {
    const liveMn = liveMnMap.get(`${String(m.txhash || '').toLowerCase()}:${Number(m.outidx)}`)
    if (!liveMn) continue
    const livePk = String(liveMn.pubkey || '').trim()
    const memberPk = String(m.pubkey || '').trim()
    const explicitOpPk = String(m.operatorPubKey || m.blsPubKey || '').trim()
    const operatorPubKey =
      (/^[0-9a-fA-F]{96}$/.test(explicitOpPk) ? explicitOpPk : '') ||
      (/^[0-9a-fA-F]{96}$/.test(livePk) ? livePk : '') ||
      (/^[0-9a-fA-F]{96}$/.test(memberPk) ? memberPk : '')
    const pubkey =
      (/^[0-9a-fA-F]{66,130}$/.test(memberPk) && memberPk.length !== 96 ? memberPk : '') ||
      livePk ||
      memberPk
    members.push({
      ...liveMn,
      ...m,
      pubkey,
      operatorPubKey: operatorPubKey || undefined,
      proTxHash: liveMn.proTxHash || m.proTxHash || undefined,
      ip: liveMn.ip || m.ip
    })
  }

  return {
    chain,
    currentHeight,
    targetHeight,
    treasuryGovernanceStartHeight: Number(
      activeQuorum?.treasuryGovernanceStartHeight ??
        blockChainInfo?.upgrades?.['Treasury Governance']?.activationheight ??
        defaults.treasuryGovernanceStartHeight
    ),
    threshold: Number(
      activeQuorum?.threshold || getQuorumMajorityThreshold(members.length || 5)
    ),
    developerFundAddress: String(activeQuorum?.developerFundAddress || defaults.devFundAddr),
    sporkPubKey: String(activeQuorum?.sporkPubKey || defaults.sporkPubKey),
    members
  }
}

export default defineEventHandler(async (event) => {
  const method = event.node.req.method
  const clientIp = resolveClientIp(event)

  if (method === 'GET') {
    const rateCheck = checkApiRateLimit('proposals-get', clientIp, 60, 60_000)
    if (!rateCheck.allowed) {
      setResponseStatus(event, 429)
      return []
    }
    return readProposalsAtomically()
  }

  if (method === 'POST') {
    const body = await readBody(event).catch(() => null)
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return { success: false, error: 'Invalid request body' }
    }

    const { action } = body as Record<string, any>

    if (action === 'create') {
      const rateCheck = checkApiRateLimit('proposals-create', clientIp, 15, 60_000)
      if (!rateCheck.allowed) {
        setResponseStatus(event, 429)
        return {
          success: false,
          error: `Rate limit exceeded. Try again in ${rateCheck.retryAfterSec}s.`
        }
      }

      const releaseLock = acquireProposalLock('proposals-write')
      if (!releaseLock) {
        setResponseStatus(event, 409)
        return {
          success: false,
          error: 'Another proposal operation is currently in progress. Please retry.'
        }
      }

      try {
        const { rawTxHex, txHash, targetAddress, amount } = body as Record<string, any>
        if (!rawTxHex || !txHash || !targetAddress || amount === undefined || amount === null) {
          return { success: false, error: 'Missing parameters' }
        }
        const cleanRawHex = String(rawTxHex).trim()
        const cleanTxHash = String(txHash).trim().toLowerCase()
        if (
          cleanRawHex.length === 0 ||
          cleanRawHex.length % 2 !== 0 ||
          cleanRawHex.length > 200000 ||
          !/^[0-9a-fA-F]+$/.test(cleanRawHex) ||
          !/^[0-9a-fA-F]{64}$/.test(cleanTxHash)
        ) {
          return { success: false, error: 'Invalid rawTxHex or txHash format/size' }
        }

        // 1. Verify txHash matches double-SHA256(rawTxHex)
        const computedTxHash = calculateTxHash(cleanRawHex).toLowerCase()
        if (computedTxHash !== cleanTxHash) {
          return {
            success: false,
            error: 'txHash does not match double-SHA256 digest of rawTxHex'
          }
        }

        // 2. Verify rawTxHex is a valid transaction spending an unspent Developer Fund UTXO signed by Spork Key
        let decodedTx: any
        let quorumInfo: any
        try {
          quorumInfo = await fetchActiveQuorumForSpend()
          decodedTx = await callRpc('decoderawtransaction', [cleanRawHex])
        } catch (err: any) {
          return {
            success: false,
            error: `Failed to decode or validate raw transaction: ${sanitizeRpcErrorMessage(err)}`
          }
        }

        if (
          quorumInfo.treasuryGovernanceStartHeight &&
          quorumInfo.targetHeight < quorumInfo.treasuryGovernanceStartHeight
        ) {
          return {
            success: false,
            error: `Developer Fund spending is not active until block #${quorumInfo.treasuryGovernanceStartHeight} (current spend height: #${quorumInfo.targetHeight})`
          }
        }

        if (
          !decodedTx ||
          !Array.isArray(decodedTx.vin) ||
          decodedTx.vin.length === 0 ||
          !Array.isArray(decodedTx.vout) ||
          decodedTx.vout.length === 0
        ) {
          return { success: false, error: 'Decoded transaction has no inputs or outputs' }
        }

        const cleanTargetAddress = normalizeTaprootAddress(String(targetAddress).trim())
        const requestedAmount = Number(amount)
        if (
          !cleanTargetAddress ||
          !isValidKristaAddress(cleanTargetAddress, quorumInfo.chain) ||
          !Number.isFinite(requestedAmount) ||
          requestedAmount <= 0 ||
          requestedAmount > 210_000_000
        ) {
          return { success: false, error: 'Invalid targetAddress or amount' }
        }

        const proposals = readProposalsAtomically()
        const pendingProposals = proposals.filter((p: any) => p.status === 'pending')
        if (pendingProposals.length >= 50) {
          return { success: false, error: 'Maximum pending proposals limit (50) reached' }
        }
        if (
          proposals.some(
            (p: any) => String(p.txHash).toLowerCase() === cleanTxHash && p.status !== 'failed'
          )
        ) {
          return { success: false, error: 'Proposal with this txHash already exists' }
        }

        for (let i = 0; i < decodedTx.vin.length; i++) {
          const vin = decodedTx.vin[i]
          if (!vin.txid || vin.vout === undefined) {
            return {
              success: false,
              error: 'Invalid coinbase or missing input outpoint in proposal transaction'
            }
          }
          // Check UTXO is unspent and belongs to Developer Fund Address
          const txOut = await callRpc('gettxout', [vin.txid, Number(vin.vout), true])
          if (!txOut) {
            return {
              success: false,
              error: `Input UTXO ${vin.txid}:${vin.vout} is already spent or does not exist`
            }
          }
          const outAddresses: string[] =
            txOut.scriptPubKey?.addresses ||
            (txOut.scriptPubKey?.address ? [txOut.scriptPubKey.address] : [])
          if (!outAddresses.includes(quorumInfo.developerFundAddress)) {
            return {
              success: false,
              error: `Input UTXO ${vin.txid}:${vin.vout} does not belong to Developer Fund (${quorumInfo.developerFundAddress})`
            }
          }

          // Check scriptSig contains <sporkSig> <sporkPubKey> and cryptographically verify Spork ECDSA signature
          const pushes = extractScriptSigPushesBytes(vin.scriptSig?.hex || '')
          if (pushes.length < 2) {
            return {
              success: false,
              error: 'Input scriptSig must be pre-signed with Spork signature and Spork public key'
            }
          }
          const sporkVerify = verifySporkInputSignature(
            cleanRawHex,
            i,
            pushes[0]!,
            pushes[1]!,
            quorumInfo.sporkPubKey
          )
          if (!sporkVerify.valid) {
            return {
              success: false,
              error: `Input #${i} invalid Spork signature: ${sporkVerify.error}`
            }
          }
        }

        // 3. Verify decodedTx.vout matches targetAddress and amount (only targetAddress and Developer Fund change allowed)
        let targetAmountSats = 0
        for (let outIdx = 0; outIdx < decodedTx.vout.length; outIdx++) {
          const vout = decodedTx.vout[outIdx]
          const voutAddresses: string[] =
            vout.scriptPubKey?.addresses ||
            (vout.scriptPubKey?.address ? [vout.scriptPubKey.address] : [])
          if (voutAddresses.length !== 1) {
            return {
              success: false,
              error: `Output #${outIdx} must have a single standard destination address`
            }
          }
          const outAddr = normalizeTaprootAddress(voutAddresses[0]!)
          const outSats = Math.round(Number(vout.value) * 1e8)
          if (outSats <= 0) {
            return { success: false, error: `Output #${outIdx} has non-positive value` }
          }
          if (outAddr === cleanTargetAddress) {
            targetAmountSats += outSats
          } else if (outAddr !== quorumInfo.developerFundAddress) {
            return {
              success: false,
              error: `Output #${outIdx} pays unauthorized address ${outAddr}; only targetAddress (${cleanTargetAddress}) and Developer Fund change (${quorumInfo.developerFundAddress}) are allowed`
            }
          }
        }

        const requestedAmountSats = Math.round(requestedAmount * 1e8)
        if (targetAmountSats <= 0 || targetAmountSats !== requestedAmountSats) {
          return {
            success: false,
            error: `Proposal amount (${requestedAmount} KRISTA) does not match transaction output total to ${cleanTargetAddress} (${targetAmountSats / 1e8} KRISTA)`
          }
        }

        const newProposal = {
          id: crypto.randomUUID(),
          rawTxHex: cleanRawHex,
          txHash: cleanTxHash,
          targetAddress: cleanTargetAddress,
          amount: targetAmountSats / 1e8,
          signatures: [],
          status: 'pending',
          createdAt: new Date().toISOString()
        }

        proposals.push(newProposal)
        writeProposalsAtomically(proposals)

        return { success: true, proposal: newProposal }
      } finally {
        releaseLock()
      }
    }

    if (action === 'sign') {
      const rateCheck = checkApiRateLimit('proposals-sign', clientIp, 30, 60_000)
      if (!rateCheck.allowed) {
        setResponseStatus(event, 429)
        return {
          success: false,
          error: `Rate limit exceeded. Try again in ${rateCheck.retryAfterSec}s.`
        }
      }

      const releaseLock = acquireProposalLock('proposals-write')
      if (!releaseLock) {
        setResponseStatus(event, 409)
        return {
          success: false,
          error: 'Another signature operation is currently in progress. Please retry.'
        }
      }

      try {
        const { proposalId, txhash, outidx, pubkey, signature } = body as Record<string, any>
        if (!proposalId || !txhash || outidx === undefined || !pubkey || !signature) {
          return { success: false, error: 'Missing parameters' }
        }
        const cleanProposalId = String(proposalId).trim()
        const cleanTxhash = String(txhash).trim().toLowerCase()
        const cleanPubkey = String(pubkey).trim()
        const cleanSignature = String(signature).trim()
        const cleanOutidx = Number(outidx)

        if (
          cleanProposalId.length > 64 ||
          !/^[0-9a-fA-F]{64}$/.test(cleanTxhash) ||
          !Number.isInteger(cleanOutidx) ||
          cleanOutidx < 0 ||
          !/^[0-9a-fA-F]{66,130}$/.test(cleanPubkey) ||
          !/^[0-9a-fA-F]{290,1024}$/.test(cleanSignature)
        ) {
          return { success: false, error: 'Invalid signature parameter format' }
        }

        const proposals = readProposalsAtomically()
        const proposal = proposals.find((p: any) => p.id === cleanProposalId)
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
          return {
            success: false,
            error: `Failed to fetch active quorum: ${sanitizeRpcErrorMessage(err)}`
          }
        }

        // 2. Verify that (txhash, outidx, pubkey|operatorPubKey) is an elected member of the active quorum
        const electedMember = quorumInfo.members.find(
          (m: any) =>
            String(m.txhash).toLowerCase() === cleanTxhash &&
            Number(m.outidx) === cleanOutidx &&
            (pubkeysMatch(String(m.pubkey), cleanPubkey) ||
              (m.operatorPubKey && blsPubKeysMatch(String(m.operatorPubKey), cleanPubkey)))
        )
        if (!electedMember) {
          return {
            success: false,
            error: 'Signer is not an elected member of the active quorum for the next block'
          }
        }

        // 3. Prune any stale signatures from previous quorum epochs so epoch boundaries never brick the proposal
        proposal.signatures = (proposal.signatures || []).filter((s: any) => {
          const stillInQuorum = quorumInfo.members.find(
            (m: any) =>
              String(m.txhash).toLowerCase() === String(s.txhash).toLowerCase() &&
              Number(m.outidx) === Number(s.outidx) &&
              (pubkeysMatch(String(m.pubkey), String(s.pubkey)) ||
                (m.operatorPubKey && blsPubKeysMatch(String(m.operatorPubKey), String(s.pubkey))))
          )
          if (!stillInQuorum) return false
          return verifyAndParseBLSSignedData(
            s.signature,
            proposal.txHash,
            stillInQuorum.pubkey,
            stillInQuorum.operatorPubKey
          ).valid
        })

        // 4. Check if already signed by this masternode in the current active quorum
        const alreadySigned = proposal.signatures.some(
          (s: any) =>
            String(s.txhash).toLowerCase() === String(electedMember.txhash).toLowerCase() &&
            Number(s.outidx) === Number(electedMember.outidx)
        )
        if (alreadySigned) {
          return { success: false, error: 'Already signed by this masternode' }
        }

        // 5. Verify KTDIP3 operator BLS or hybrid BLS12-381 + secp256k1 signature (CBLSSignedData)
        const verifyResult = verifyAndParseBLSSignedData(
          cleanSignature,
          proposal.txHash,
          electedMember.pubkey,
          electedMember.operatorPubKey
        )
        if (!verifyResult.valid) {
          return {
            success: false,
            error: verifyResult.error || 'Invalid BLS12-381 / ECDSA quorum signature'
          }
        }

        // Save the signature using canonical quorum member fields
        proposal.signatures.push({
          txhash: electedMember.txhash,
          outidx: Number(electedMember.outidx),
          pubkey: cleanSignature.length === 290 && electedMember.operatorPubKey
            ? electedMember.operatorPubKey
            : electedMember.pubkey,
          operatorPubKey: electedMember.operatorPubKey,
          signature: cleanSignature,
          timestamp: Date.now()
        })

        const threshold = quorumInfo.threshold

        if (proposal.signatures.length >= threshold) {
          // Verify aggregated BLS12-381 signature across all signing quorum members (matching src/llmq.cpp:101-105)
          const aggCheck = verifyAggregatedBLSSignatures(proposal.txHash, proposal.signatures)
          if (!aggCheck.valid) {
            return {
              success: false,
              error: aggCheck.error || 'Aggregated BLS12-381 quorum signature verification failed'
            }
          }

          // Serialize CQuorumSignature and inject into all transaction inputs
          const qsigBuf = serializeQuorumSignatureBytes(proposal.txHash, proposal.signatures)
          const qsigPush = concatBytes(getPushDataPrefixBytes(qsigBuf.length), qsigBuf)

          const finalTxBuf = injectQuorumSigIntoRawTxBytes(proposal.rawTxHex, qsigPush)
          const finalTxHex = bytesToHex(finalTxBuf)

          try {
            const broadcastResult = await callRpc('sendrawtransaction', [finalTxHex])
            proposal.status = 'broadcasted'
            proposal.finalTxid = broadcastResult
            proposal.broadcastTxId = broadcastResult
            proposal.finalTxHex = finalTxHex
            delete proposal.error
            delete proposal.broadcastError
          } catch (broadcastErr: any) {
            // Do not permanently lock the proposal in 'failed' state if the UTXO is still unspent
            const safeErr = sanitizeRpcErrorMessage(broadcastErr)
            proposal.error = safeErr
            proposal.broadcastError = safeErr
            try {
              const decoded = await callRpc('decoderawtransaction', [proposal.rawTxHex])
              const firstVin = decoded?.vin?.[0]
              const txOut = firstVin
                ? await callRpc('gettxout', [firstVin.txid, Number(firstVin.vout), true])
                : null
              if (!txOut) {
                proposal.status = 'failed'
              }
            } catch {
              // Keep status = 'pending' so quorum members can retry after epoch/sync transition
            }
          }
        }

        writeProposalsAtomically(proposals)
        return { success: true, proposal }
      } finally {
        releaseLock()
      }
    }

    return { success: false, error: 'Unsupported action' }
  }

  setResponseStatus(event, 405)
  return { error: 'Method not allowed' }
})
