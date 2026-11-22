<script setup lang="ts">
import { ref, computed } from 'vue'
import { useI18n } from '~/composables/useI18n'
import {
  CORE_VERSION,
  PROTOCOL_VERSION,
  blsPubKeysMatch,
  deriveBlsPubKeyFromSecret,
  derivePubKeysFromWIF,
  getQuorumMajorityThreshold,
  pubkeysMatch,
  createHybridBLSSignedData,
  createOperatorBLSSignedData
} from '~/utils/treasuryCrypto'

interface QuorumMember {
  rank?: number
  txhash: string
  outidx: number
  pubkey: string
  operatorPubKey?: string
  dip3?: boolean
  addr?: string
  status?: string
  ip?: string
}

interface QuorumResponse {
  success: boolean
  coreVersion?: string
  protocolVersion?: number
  chain?: string
  currentHeight?: number
  targetHeight?: number
  dkgHeight?: number
  quorumHash?: string
  seedHeight?: number
  seed?: string
  developerFundAddress?: string
  sporkPubKey?: string
  treasuryGovernanceStartHeight?: number
  activeMasternodeCount?: number
  totalMasternodeCount?: number
  targetQuorumSize?: number
  threshold?: number
  members?: QuorumMember[]
  error?: string
}

interface ProposalSignature {
  txhash: string
  outidx: number
  pubkey: string
  signature: string
  timestamp?: number
}

interface ProposalItem {
  id: string
  txHash: string
  rawTxHex: string
  targetAddress: string
  amount: number
  signatures: ProposalSignature[]
  status: 'pending' | 'broadcasted' | 'failed'
  finalTxid?: string
  broadcastTxId?: string
  error?: string
  broadcastError?: string
  createdAt: string | number
}

const { t } = useI18n()
const toast = useToast()

const {
  data: quorumData,
  pending: quorumLoading,
  refresh: refreshQuorum
} = await useFetch<QuorumResponse>('/api/quorum')

const {
  data: proposals,
  pending: proposalsLoading,
  refresh: refreshProposals
} = await useFetch<ProposalItem[]>('/api/proposals')

const selectedNode = ref('')
const wifKey = ref('')
const showWif = ref(false)
const wifTouched = ref(false)
const isSigning = ref(false)
const statusFilter = ref<'all' | 'pending' | 'broadcasted' | 'failed'>('all')
const searchQuery = ref('')

function getMemberKey(member: QuorumMember): string {
  return `${String(member.txhash).toLowerCase()}:${Number(member.outidx)}`
}

const quorumMembers = computed<QuorumMember[]>(() => {
  return Array.isArray(quorumData.value?.members) ? quorumData.value!.members! : []
})

// Derive public keys reactively from WIF or 64-hex KTDIP3 BLS Operator Secret (strictly in browser memory)
const derivedWallet = computed(() => {
  const clean = wifKey.value.trim()
  if (!clean) return null
  try {
    if (/^[0-9a-fA-F]{64}$/.test(clean)) {
      const bls = deriveBlsPubKeyFromSecret(clean)
      return {
        mode: 'bls-operator' as const,
        blsSecretHex: bls.blsSecretHex,
        blsPubKeyHex: bls.blsPubKeyHex,
        compressedPubKey: bls.blsPubKeyHex
      }
    }
    const wif = derivePubKeysFromWIF(clean)
    return {
      mode: 'wif' as const,
      ...wif
    }
  } catch {
    return null
  }
})

const matchedQuorumMember = computed<QuorumMember | null>(() => {
  if (!derivedWallet.value || quorumMembers.value.length === 0) return null
  for (const member of quorumMembers.value) {
    if (derivedWallet.value.mode === 'bls-operator') {
      const candidateOp = member.operatorPubKey || member.pubkey
      if (blsPubKeysMatch(derivedWallet.value.blsPubKeyHex, candidateOp)) {
        return member
      }
    } else if (pubkeysMatch(derivedWallet.value.compressedPubKey, member.pubkey)) {
      return member
    }
  }
  return null
})

// Auto-select matched node in dropdown when WIF matches a quorum member
function syncSelectedNodeFromWif() {
  if (matchedQuorumMember.value) {
    selectedNode.value = getMemberKey(matchedQuorumMember.value)
  }
}

function onWifInput() {
  if (wifTouched.value && derivedWallet.value) {
    wifTouched.value = false
  }
  syncSelectedNodeFromWif()
}

function onWifBlur() {
  if (wifKey.value.trim().length > 0) {
    wifTouched.value = true
  }
  syncSelectedNodeFromWif()
}

function clearWifKey() {
  wifKey.value = ''
  wifTouched.value = false
  showWif.value = false
}

const wifHasError = computed(() => {
  return wifTouched.value && wifKey.value.trim().length > 0 && !derivedWallet.value
})

const quorumSize = computed(
  () => quorumMembers.value.length || quorumData.value?.targetQuorumSize || 5
)

const quorumThreshold = computed(() => {
  if (quorumData.value?.threshold) {
    return Number(quorumData.value.threshold)
  }
  return getQuorumMajorityThreshold(quorumSize.value)
})

const pendingProposalsCount = computed(() => {
  if (!proposals.value) return 0
  return proposals.value.filter((p) => p.status === 'pending').length
})

const totalProposalVolume = computed(() => {
  if (!proposals.value) return 0
  return proposals.value.reduce((acc, item) => acc + (Number(item.amount) || 0), 0)
})

const filteredProposals = computed(() => {
  if (!proposals.value) return []
  const query = searchQuery.value.trim().toLowerCase()
  return proposals.value.filter((p) => {
    if (statusFilter.value !== 'all' && p.status !== statusFilter.value) {
      return false
    }
    if (!query) return true
    return (
      p.targetAddress.toLowerCase().includes(query) ||
      p.txHash.toLowerCase().includes(query) ||
      p.id.toLowerCase().includes(query)
    )
  })
})

function hasNodeSigned(proposal: ProposalItem, memberKey: string): boolean {
  if (!memberKey || !proposal.signatures) return false
  return proposal.signatures.some(
    (s) => `${String(s.txhash).toLowerCase()}:${Number(s.outidx)}` === memberKey.toLowerCase()
  )
}

async function copyText(value: string) {
  if (!value || typeof navigator === 'undefined' || !navigator.clipboard) return
  try {
    await navigator.clipboard.writeText(value)
    toast.add({
      title: t('copiedToast'),
      color: 'success'
    })
  } catch {
    // Ignore clipboard failure
  }
}

async function refreshAll() {
  await Promise.all([refreshQuorum(), refreshProposals()])
}

async function signProposal(proposal: ProposalItem) {
  if (!selectedNode.value || !wifKey.value.trim()) {
    wifTouched.value = true
    toast.add({
      title: t('toastMissingTitle'),
      description: t('toastMissingSignDesc'),
      color: 'warning'
    })
    return
  }

  isSigning.value = true
  try {
    const cleanWif = wifKey.value.trim()
    let wallet:
      | ({ mode: 'bls-operator' } & ReturnType<typeof deriveBlsPubKeyFromSecret>)
      | ({ mode: 'wif' } & ReturnType<typeof derivePubKeysFromWIF>)
    try {
      if (/^[0-9a-fA-F]{64}$/.test(cleanWif)) {
        wallet = { mode: 'bls-operator', ...deriveBlsPubKeyFromSecret(cleanWif) }
      } else {
        wallet = { mode: 'wif', ...derivePubKeysFromWIF(cleanWif) }
      }
    } catch {
      wifTouched.value = true
      throw new Error(t('quorumInvalidWifDesc'))
    }

    const activeNode = quorumMembers.value.find(
      (n) => getMemberKey(n) === selectedNode.value.toLowerCase()
    )
    if (!activeNode) {
      throw new Error(t('toastMissingSignDesc'))
    }

    let signedDataHex = ''
    let signerPubkey = activeNode.pubkey
    if (wallet.mode === 'bls-operator') {
      const candidateOp = activeNode.operatorPubKey || activeNode.pubkey
      if (!blsPubKeysMatch(wallet.blsPubKeyHex, candidateOp)) {
        throw new Error(t('toastKeyMismatch'))
      }
      signedDataHex = createOperatorBLSSignedData(wallet.blsSecretHex, proposal.txHash).signedDataHex
      signerPubkey = candidateOp
    } else {
      if (!pubkeysMatch(wallet.compressedPubKey, activeNode.pubkey)) {
        throw new Error(t('toastKeyMismatch'))
      }
      signedDataHex = createHybridBLSSignedData(wallet.privKeyHex, proposal.txHash).signedDataHex
    }

    const res = await $fetch<{ success: boolean; error?: string }>('/api/proposals', {
      method: 'POST',
      body: {
        action: 'sign',
        proposalId: proposal.id,
        txhash: activeNode.txhash,
        outidx: Number(activeNode.outidx),
        pubkey: signerPubkey,
        signature: signedDataHex
      }
    })

    if (!res?.success) {
      throw new Error(res?.error || t('toastSignErrorTitle'))
    }

    toast.add({
      title: t('toastSignSuccessTitle'),
      description: t('toastSignSuccessDesc'),
      color: 'success'
    })

    await refreshProposals()
  } catch (err: unknown) {
    const fetchErr = err as { data?: { statusMessage?: string; error?: string }; message?: string }
    const errMsg =
      fetchErr?.data?.error || fetchErr?.data?.statusMessage || fetchErr?.message || String(err)
    toast.add({
      title: t('toastSignErrorTitle'),
      description: errMsg,
      color: 'error'
    })
  } finally {
    isSigning.value = false
  }
}
</script>

<template>
  <div class="space-y-8">
    <!-- Hero Banner -->
    <section
      class="krista-card krista-hero-glow p-6 sm:p-8 border border-[var(--krista-border)] relative"
    >
      <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div class="space-y-3 max-w-3xl">
          <div class="flex flex-wrap items-center gap-2.5">
            <span
              class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-[#7695CD]/15 text-[#7695CD] border border-[#7695CD]/35"
            >
              <span class="w-2 h-2 rounded-full bg-[#7695CD] animate-pulse"></span>
              {{ t('heroBadge') }}
            </span>

            <span
              class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-[#7695CD]/10 text-[#7695CD] border border-[#7695CD]/30"
            >
              Core {{ quorumData?.coreVersion || CORE_VERSION }} &bull; Proto {{ quorumData?.protocolVersion || PROTOCOL_VERSION }}
            </span>

            <span
              v-if="quorumData?.chain"
              class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-[#F5897C]/15 text-[#F5897C] border border-[#F5897C]/35"
            >
              {{ quorumData.chain.toUpperCase() }}
            </span>

            <span
              class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
              :class="
                quorumData?.success
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
              "
            >
              <span
                class="w-1.5 h-1.5 rounded-full"
                :class="quorumData?.success ? 'bg-emerald-400' : 'bg-amber-400'"
              ></span>
              {{ quorumData?.success ? t('networkConnected') : t('networkOffline') }}
            </span>
          </div>

          <h1 class="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-[var(--krista-text)]">
            {{ t('heroTitle') }}
          </h1>

          <p class="text-sm sm:text-base text-[var(--krista-text-muted)] leading-relaxed">
            {{ t('heroDescription') }}
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            :disabled="quorumLoading || proposalsLoading"
            class="px-4 py-2.5 rounded-xl text-sm font-semibold border border-[var(--krista-border)] bg-[var(--krista-surface)] text-[var(--krista-text)] hover:border-[#7695CD] transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            @click="refreshAll"
          >
            <svg
              aria-hidden="true"
              class="w-4 h-4 text-[#7695CD]"
              :class="{ 'animate-spin': quorumLoading || proposalsLoading }"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            <span>{{ t('refreshBtn') }}</span>
          </button>

          <NuxtLink
            to="/admin"
            class="px-5 py-2.5 rounded-xl text-sm font-bold text-white bg-gradient-to-r from-[#7695CD] to-[#F5897C] hover:opacity-95 shadow-md transition-all flex items-center gap-2"
          >
            <svg
              aria-hidden="true"
              class="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2.5"
            >
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            <span>{{ t('navCreateProposal') }}</span>
          </NuxtLink>
        </div>
      </div>
    </section>

    <!-- 4-Card Institutional KPI Strip -->
    <section aria-label="Consensus Metrics" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <!-- KPI 1: Block Height H & Spend Block H+1 -->
      <div class="krista-card p-5 flex flex-col justify-between">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
            {{ t('kpiCurrentBlock') }}
          </span>
          <span class="p-2 rounded-lg bg-[#7695CD]/15 text-[#7695CD]">
            <svg
              aria-hidden="true"
              class="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
              />
            </svg>
          </span>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-2xl font-extrabold font-mono text-[var(--krista-text)]">
            #{{ quorumData?.currentHeight ?? 0 }}
          </span>
          <span class="text-xs font-mono text-[#7695CD]">
            &rarr; H+1: #{{ quorumData?.targetHeight ?? (quorumData?.currentHeight ?? 0) + 1 }}
          </span>
        </div>
        <p class="mt-1 text-xs text-[var(--krista-text-muted)]">
          {{ t('kpiTargetSpendBlock') }}
        </p>
      </div>

      <!-- KPI 2: Active DKG & Majority Threshold -->
      <div class="krista-card p-5 flex flex-col justify-between">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
            {{ t('kpiDkgEpoch') }}
          </span>
          <span class="p-2 rounded-lg bg-[#F5897C]/15 text-[#F5897C]">
            <svg
              aria-hidden="true"
              class="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
          </span>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-2xl font-extrabold font-mono text-[#F5897C]">
            {{ quorumThreshold }} / {{ quorumSize }}
          </span>
          <span class="text-xs font-mono text-[var(--krista-text-muted)]">
            (DKG #{{ quorumData?.dkgHeight ?? 0 }})
          </span>
        </div>
        <p class="mt-1 text-xs text-[var(--krista-text-muted)]">
          {{ t('kpiMajorityRule') }}
        </p>
      </div>

      <!-- KPI 3: Active Proposals & Volume -->
      <div class="krista-card p-5 flex flex-col justify-between">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
            {{ t('kpiActiveProposals') }}
          </span>
          <span class="p-2 rounded-lg bg-[#7695CD]/15 text-[#7695CD]">
            <svg
              aria-hidden="true"
              class="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
          </span>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-2xl font-extrabold font-mono text-[var(--krista-text)]">
            {{ pendingProposalsCount }}
          </span>
          <span class="text-xs font-mono text-[#F5897C]">
            {{ totalProposalVolume.toLocaleString() }} KRISTA
          </span>
        </div>
        <p class="mt-1 text-xs text-[var(--krista-text-muted)]">
          {{ t('kpiPendingVolume') }}
        </p>
      </div>

      <!-- KPI 4: Zero-Custody Client-Side Security -->
      <div class="krista-card p-5 flex flex-col justify-between">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
            {{ t('kpiZeroCustody') }}
          </span>
          <span class="p-2 rounded-lg bg-emerald-500/15 text-emerald-400">
            <svg
              aria-hidden="true"
              class="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
          </span>
        </div>
        <div class="mt-3 flex items-center gap-2">
          <span class="text-lg font-extrabold text-emerald-400">
            CBLSSignedData
          </span>
        </div>
        <p class="mt-1 text-xs text-[var(--krista-text-muted)]">
          {{ t('kpiZeroCustodyDesc') }}
        </p>
      </div>
    </section>

    <!-- Masternode Voter Verification & Local Key Readiness -->
    <section
      aria-labelledby="voter-verifier-heading"
      class="krista-card p-6 border-l-4 border-l-[#7695CD]"
    >
      <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
        <div class="space-y-1.5 lg:max-w-xl">
          <div class="flex items-center gap-2">
            <svg
              aria-hidden="true"
              class="w-5 h-5 text-[#F5897C]"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
              />
            </svg>
            <h2 id="voter-verifier-heading" class="text-lg font-bold text-[var(--krista-text)]">
              {{ t('voterVerifierTitle') }}
            </h2>
          </div>
          <p class="text-xs sm:text-sm text-[var(--krista-text-muted)]">
            {{ t('voterVerifierDesc') }}
          </p>
        </div>

        <div class="flex-1 max-w-2xl w-full space-y-3">
          <div class="krista-field-group p-3 rounded-xl border border-[var(--krista-border)] bg-[var(--krista-surface)]">
            <label
              for="verifier-wif-input"
              class="block text-xs font-bold uppercase tracking-wider text-[var(--krista-text)] mb-1"
            >
              {{ t('wifInputLabel') }}
            </label>
            <!-- Format hint placed ABOVE the input so autocomplete popovers never cover it -->
            <p id="verifier-wif-hint" class="text-xs text-[var(--krista-text-muted)] mb-2">
              {{ t('wifInputHint') }}
            </p>

            <div class="flex items-center gap-2">
              <input
                id="verifier-wif-input"
                v-model="wifKey"
                :type="showWif ? 'text' : 'password'"
                autocomplete="off"
                spellcheck="false"
                :placeholder="t('wifInputPlaceholder')"
                aria-describedby="verifier-wif-hint verifier-wif-error"
                :aria-invalid="wifHasError ? 'true' : undefined"
                class="krista-input flex-1 px-3.5 py-2 rounded-lg text-sm font-mono bg-[var(--krista-bg-elevated)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none"
                @input="onWifInput"
                @blur="onWifBlur"
              />

              <button
                type="button"
                :aria-label="showWif ? t('wifHidePassword') : t('wifShowPassword')"
                :title="showWif ? t('wifHidePassword') : t('wifShowPassword')"
                class="px-3 py-2 rounded-lg border border-[var(--krista-border)] bg-[var(--krista-bg-elevated)] text-xs font-semibold text-[var(--krista-text-muted)] hover:text-[var(--krista-text)] cursor-pointer"
                @click="showWif = !showWif"
              >
                {{ showWif ? '🙈' : '👁️' }}
              </button>

              <button
                v-if="wifKey"
                type="button"
                class="px-3 py-2 rounded-lg border border-[var(--krista-border)] bg-[var(--krista-bg-elevated)] text-xs font-semibold text-[#F5897C] hover:bg-[#F5897C]/10 cursor-pointer"
                @click="clearWifKey"
              >
                {{ t('wifClearBtn') }}
              </button>
            </div>

            <!-- Accessible Error Announcement -->
            <p
              v-if="wifHasError"
              id="verifier-wif-error"
              role="alert"
              class="mt-2 text-xs font-semibold text-red-400"
            >
              {{ t('quorumInvalidWifTitle') }}: {{ t('quorumInvalidWifDesc') }}
            </p>
          </div>

          <!-- Instant Quorum Match Status Banner -->
          <div
            v-if="derivedWallet && matchedQuorumMember"
            role="status"
            class="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/35 flex items-start gap-3"
          >
            <span class="p-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 shrink-0 mt-0.5">
              <svg
                aria-hidden="true"
                class="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2.5"
              >
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </span>
            <div class="text-xs space-y-1">
              <p class="font-bold text-emerald-400">
                {{ t('quorumMatchedTitle') }} ({{ matchedQuorumMember.ip || matchedQuorumMember.addr || 'On-Chain MN' }})
              </p>
              <p class="text-[var(--krista-text-muted)]">
                {{ t('quorumMatchedDesc') }}
              </p>
            </div>
          </div>

          <div
            v-else-if="derivedWallet && !matchedQuorumMember"
            role="status"
            class="p-3.5 rounded-xl bg-[#F5897C]/10 border border-[#F5897C]/35 flex items-start gap-3"
          >
            <span class="p-1.5 rounded-lg bg-[#F5897C]/20 text-[#F5897C] shrink-0 mt-0.5">
              <svg
                aria-hidden="true"
                class="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </span>
            <div class="text-xs space-y-1">
              <p class="font-bold text-[#F5897C]">
                {{ t('quorumNotMatchedTitle') }}
              </p>
              <p class="text-[var(--krista-text-muted)]">
                {{ t('quorumNotMatchedDesc') }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Network Telemetry + Active Quorum Members Table -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <!-- Left 4 Columns: Network & Consensus Telemetry -->
      <section class="lg:col-span-4 krista-card p-6 space-y-5">
        <div class="flex items-center justify-between border-b border-[var(--krista-border)] pb-3">
          <h2 class="text-base font-bold text-[var(--krista-text)] flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-[#7695CD]"></span>
            {{ t('networkStatusTitle') }}
          </h2>
          <span
            v-if="quorumData?.chain"
            class="text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-[#7695CD]/15 text-[#7695CD]"
          >
            {{ quorumData.chain }}
          </span>
        </div>

        <dl class="space-y-3 text-sm">
          <div class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60">
            <dt class="text-[var(--krista-text-muted)]">{{ t('currentBlockHeight') }}</dt>
            <dd class="font-mono font-bold text-[var(--krista-text)]">
              #{{ quorumData?.currentHeight ?? 0 }}
            </dd>
          </div>

          <div class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60">
            <dt class="text-[var(--krista-text-muted)]">{{ t('targetSpendHeight') }}</dt>
            <dd class="font-mono font-bold text-[#7695CD]">
              #{{ quorumData?.targetHeight ?? (quorumData?.currentHeight ?? 0) + 1 }}
            </dd>
          </div>

          <div class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60">
            <dt class="text-[var(--krista-text-muted)]">{{ t('activeDkgHeight') }}</dt>
            <dd class="font-mono font-bold text-[#F5897C]">
              #{{ quorumData?.dkgHeight ?? 0 }}
            </dd>
          </div>

          <div class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60">
            <dt class="text-[var(--krista-text-muted)]">{{ t('activeSeedHeight') }}</dt>
            <dd class="font-mono font-semibold text-[var(--krista-text)]">
              #{{ quorumData?.seedHeight ?? 0 }}
            </dd>
          </div>

          <div
            v-if="quorumData?.treasuryGovernanceStartHeight"
            class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60"
          >
            <dt class="text-[var(--krista-text-muted)]">{{ t('governanceStartHeight') }}</dt>
            <dd class="font-mono font-semibold text-emerald-400">
              #{{ quorumData.treasuryGovernanceStartHeight }}
            </dd>
          </div>

          <div class="flex items-center justify-between py-1.5 border-b border-[var(--krista-border)]/60">
            <dt class="text-[var(--krista-text-muted)]">{{ t('liveMasternodesLabel') }}</dt>
            <dd
              class="font-mono font-bold"
              :class="
                (quorumData?.activeMasternodeCount ?? quorumMembers.length) > 0
                  ? 'text-emerald-400'
                  : 'text-amber-400'
              "
            >
              {{ quorumData?.activeMasternodeCount ?? quorumMembers.length }}
            </dd>
          </div>
        </dl>

        <!-- Developer Fund Address -->
        <div v-if="quorumData?.developerFundAddress" class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
              {{ t('devFundAddressLabel') }}
            </span>
            <button
              type="button"
              class="text-xs font-semibold text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
              @click="copyText(quorumData.developerFundAddress)"
            >
              {{ t('copyBtn') }}
            </button>
          </div>
          <div
            class="p-2.5 rounded-lg bg-[var(--krista-surface)] border border-[var(--krista-border)] font-mono text-xs text-[#F5897C] break-all"
          >
            {{ quorumData.developerFundAddress }}
          </div>
        </div>

        <!-- Deterministic Quorum Seed -->
        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
              {{ t('activeQuorumSeed') }}
            </span>
            <button
              v-if="quorumData?.seed"
              type="button"
              class="text-xs font-semibold text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
              @click="copyText(quorumData.seed)"
            >
              {{ t('copyBtn') }}
            </button>
          </div>
          <div
            class="p-2.5 rounded-lg bg-[var(--krista-surface)] border border-[var(--krista-border)] font-mono text-[11px] text-[var(--krista-text-muted)] break-all"
          >
            {{ quorumData?.seed || '0000000000000000000000000000000000000000000000000000000000000000' }}
          </div>
        </div>
      </section>

      <!-- Right 8 Columns: Active Quorum Members Table -->
      <section class="lg:col-span-8 krista-card p-6 flex flex-col justify-between">
        <div>
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-[var(--krista-border)] pb-3 mb-4">
            <div>
              <h2 class="text-base font-bold text-[var(--krista-text)]">
                {{ t('quorumMembersTitle') }}
              </h2>
              <p class="text-xs text-[var(--krista-text-muted)]">
                {{ t('quorumMembersSubtitle') }}
              </p>
            </div>
            <div class="flex flex-wrap items-center gap-2 self-start sm:self-auto">
              <span
                class="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold bg-[#F5897C]/15 text-[#F5897C] border border-[#F5897C]/30"
              >
                {{ t('quorumScalingNote') }}
              </span>
              <span
                class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border"
                :class="
                  quorumMembers.length > 0
                    ? 'bg-[#7695CD]/15 text-[#7695CD] border-[#7695CD]/30'
                    : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                "
              >
                {{ quorumMembers.length }} / {{ quorumSize }} Masternode
              </span>
            </div>
          </div>

          <div v-if="quorumMembers.length > 0" class="overflow-x-auto custom-scroll">
            <table class="w-full text-left border-collapse">
              <thead>
                <tr class="border-b border-[var(--krista-border)] text-[11px] font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
                  <th scope="col" class="py-2.5 px-3">{{ t('colRank') }}</th>
                  <th scope="col" class="py-2.5 px-3">{{ t('colIpAddress') }}</th>
                  <th scope="col" class="py-2.5 px-3">{{ t('colCollateral') }}</th>
                  <th scope="col" class="py-2.5 px-3">{{ t('colPubKey') }}</th>
                  <th scope="col" class="py-2.5 px-3 text-right">{{ t('colRole') }}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[var(--krista-border)]/60 text-xs">
                <tr
                  v-for="(node, idx) in quorumMembers"
                  :key="getMemberKey(node)"
                  class="transition-colors"
                  :class="
                    matchedQuorumMember && getMemberKey(matchedQuorumMember) === getMemberKey(node)
                      ? 'bg-emerald-500/10'
                      : 'hover:bg-[#7695CD]/5'
                  "
                >
                  <td class="py-3 px-3 font-mono font-bold text-[#7695CD]">
                    #{{ node.rank ?? idx + 1 }}
                  </td>
                  <td class="py-3 px-3 font-mono font-semibold text-[var(--krista-text)]">
                    {{ node.ip || node.addr || 'On-Chain MN' }}
                  </td>
                  <td class="py-3 px-3 font-mono text-[var(--krista-text-muted)]">
                    <div class="flex items-center gap-1.5">
                      <span>{{ node.txhash.slice(0, 12) }}...{{ node.txhash.slice(-6) }}:{{ node.outidx }}</span>
                      <button
                        type="button"
                        :title="t('copyBtn')"
                        class="text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
                        @click="copyText(`${node.txhash}:${node.outidx}`)"
                      >
                        ⧉
                      </button>
                    </div>
                  </td>
                  <td class="py-3 px-3 font-mono text-[var(--krista-text-muted)]">
                    <div v-if="node.pubkey" class="flex items-center gap-1.5">
                      <span>{{ node.pubkey.slice(0, 10) }}...{{ node.pubkey.slice(-6) }}</span>
                      <button
                        type="button"
                        :title="t('copyBtn')"
                        class="text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
                        @click="copyText(node.pubkey)"
                      >
                        ⧉
                      </button>
                    </div>
                    <span v-else>-</span>
                  </td>
                  <td class="py-3 px-3 text-right">
                    <div class="inline-flex items-center justify-end gap-1.5">
                      <span
                        v-if="node.dip3 || node.operatorPubKey"
                        class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#F5897C]/15 text-[#F5897C] border border-[#F5897C]/30"
                      >
                        KTDIP3
                      </span>
                      <span
                        v-if="matchedQuorumMember && getMemberKey(matchedQuorumMember) === getMemberKey(node)"
                        class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                      >
                        {{ t('badgeYourNode') }}
                      </span>
                      <span
                        v-else
                        class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-[#7695CD]/15 text-[#7695CD] border border-[#7695CD]/30"
                      >
                        {{ t('badgeVoter') }}
                      </span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div
            v-else
            role="status"
            class="my-4 p-8 rounded-2xl border border-dashed border-[var(--krista-border)] bg-[var(--krista-surface)]/70 flex flex-col items-center justify-center text-center space-y-3"
          >
            <div class="w-12 h-12 rounded-2xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <svg
                aria-hidden="true"
                class="w-6 h-6"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
                />
              </svg>
            </div>
            <h3 class="text-base font-bold text-[var(--krista-text)]">
              {{ t('noActiveMasternodesTitle') }}
            </h3>
            <p class="text-xs sm:text-sm text-[var(--krista-text-muted)] max-w-xl leading-relaxed">
              {{ t('noActiveMasternodesDesc') }}
            </p>
            <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--krista-bg-elevated)] border border-[var(--krista-border)] font-mono text-xs text-[var(--krista-text-muted)]">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>
                RPC #{{ quorumData?.currentHeight ?? 0 }} &bull; listmasternodes: {{ quorumData?.activeMasternodeCount ?? 0 }} ENABLED
              </span>
            </div>
          </div>
        </div>
      </section>
    </div>

    <!-- Treasury Spending Proposals & Voting Section -->
    <section aria-labelledby="proposals-heading" class="space-y-5">
      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <h2 id="proposals-heading" class="text-xl font-extrabold text-[var(--krista-text)] flex items-center gap-2.5">
          <span class="w-3 h-3 rounded-sm bg-gradient-to-br from-[#7695CD] to-[#F5897C]"></span>
          {{ t('proposalsSectionTitle') }}
        </h2>

        <!-- Filter Tabs & Search -->
        <div class="flex flex-wrap items-center gap-3">
          <div
            role="group"
            aria-label="Proposal Status Filter"
            class="inline-flex rounded-xl p-1 bg-[var(--krista-surface)] border border-[var(--krista-border)]"
          >
            <button
              v-for="tab in (['all', 'pending', 'broadcasted', 'failed'] as const)"
              :key="tab"
              type="button"
              class="px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer"
              :class="
                statusFilter === tab
                  ? 'bg-[#7695CD] text-white shadow-xs'
                  : 'text-[var(--krista-text-muted)] hover:text-[var(--krista-text)]'
              "
              @click="statusFilter = tab"
            >
              {{
                tab === 'all'
                  ? t('filterAll')
                  : tab === 'pending'
                    ? t('filterPending')
                    : tab === 'broadcasted'
                      ? t('filterBroadcasted')
                      : t('filterFailed')
              }}
            </button>
          </div>

          <input
            v-model="searchQuery"
            type="search"
            :placeholder="t('searchPlaceholder')"
            :aria-label="t('searchPlaceholder')"
            class="px-3.5 py-2 rounded-xl text-xs bg-[var(--krista-surface)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none focus:border-[#7695CD] min-w-[230px]"
          />
        </div>
      </div>

      <!-- Empty State -->
      <div
        v-if="filteredProposals.length === 0"
        class="krista-card p-12 text-center space-y-4"
      >
        <div
          class="w-14 h-14 mx-auto rounded-2xl bg-[#7695CD]/15 border border-[#7695CD]/30 flex items-center justify-center text-[#7695CD]"
        >
          <svg
            aria-hidden="true"
            class="w-7 h-7"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="1.8"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
            />
          </svg>
        </div>
        <h3 class="text-lg font-bold text-[var(--krista-text)]">
          {{ t('noProposalsTitle') }}
        </h3>
        <p class="text-sm text-[var(--krista-text-muted)] max-w-md mx-auto">
          {{ t('noProposalsDesc') }}
        </p>
        <div class="pt-2">
          <NuxtLink
            to="/admin"
            class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#7695CD] to-[#F5897C] shadow-sm"
          >
            + {{ t('navCreateProposal') }}
          </NuxtLink>
        </div>
      </div>

      <!-- Proposal Cards Grid -->
      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <article
          v-for="proposal in filteredProposals"
          :key="proposal.id"
          class="krista-card p-6 flex flex-col justify-between space-y-5"
        >
          <div class="space-y-4">
            <!-- Header Row: Status Badge + Amount -->
            <div class="flex items-start justify-between gap-4 border-b border-[var(--krista-border)] pb-4">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span
                    class="px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider"
                    :class="
                      proposal.status === 'broadcasted'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/35'
                        : proposal.status === 'failed'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/35'
                          : 'bg-[#7695CD]/20 text-[#7695CD] border border-[#7695CD]/35'
                    "
                  >
                    {{
                      proposal.status === 'broadcasted'
                        ? t('statusBroadcasted')
                        : proposal.status === 'failed'
                          ? t('statusFailed')
                          : t('statusPending')
                    }}
                  </span>
                  <span class="text-xs font-semibold text-[var(--krista-text-muted)]">
                    {{ t('proposalCardBadge') }}
                  </span>
                </div>
                <p class="text-xs text-[var(--krista-text-muted)] font-mono">
                  {{ new Date(proposal.createdAt).toLocaleString() }}
                </p>
              </div>

              <div class="text-right">
                <span class="text-2xl font-extrabold font-mono text-[#F5897C]">
                  {{ proposal.amount }}
                </span>
                <span class="text-xs font-bold text-[#7695CD] ml-1">KRISTA</span>
              </div>
            </div>

            <!-- Recipient Address & Proposal txHash -->
            <div class="space-y-2.5 text-xs">
              <div class="p-3 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1">
                <div class="flex items-center justify-between text-[var(--krista-text-muted)]">
                  <span class="font-semibold">{{ t('recipientAddress') }}</span>
                  <button
                    type="button"
                    class="text-[#7695CD] hover:text-[#F5897C] font-semibold cursor-pointer"
                    @click="copyText(proposal.targetAddress)"
                  >
                    {{ t('copyBtn') }}
                  </button>
                </div>
                <p class="font-mono font-bold text-[var(--krista-text)] break-all">
                  {{ proposal.targetAddress }}
                </p>
              </div>

              <div class="p-3 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1">
                <div class="flex items-center justify-between text-[var(--krista-text-muted)]">
                  <span class="font-semibold">{{ t('proposalTxHash') }}</span>
                  <button
                    type="button"
                    class="text-[#7695CD] hover:text-[#F5897C] font-semibold cursor-pointer"
                    @click="copyText(proposal.txHash)"
                  >
                    {{ t('copyBtn') }}
                  </button>
                </div>
                <p class="font-mono text-[11px] text-[#7695CD] break-all">
                  {{ proposal.txHash }}
                </p>
              </div>
            </div>

            <!-- Quorum Signature Progress Bar -->
            <div class="space-y-2">
              <div class="flex items-center justify-between text-xs">
                <span class="font-bold text-[var(--krista-text)]">
                  {{ t('collectedSignatures') }}
                </span>
                <span class="font-mono font-bold text-[#F5897C]">
                  {{ proposal.signatures?.length || 0 }} / {{ quorumThreshold }}
                </span>
              </div>
              <progress
                class="krista-progress"
                :value="proposal.signatures?.length || 0"
                :max="quorumThreshold"
              ></progress>

              <!-- Signed Nodes Badges -->
              <div v-if="proposal.signatures?.length" class="pt-1 space-y-1">
                <span class="text-[11px] text-[var(--krista-text-muted)]">
                  {{ t('signedNodesLabel') }}
                </span>
                <div class="flex flex-wrap gap-1.5">
                  <span
                    v-for="sig in proposal.signatures"
                    :key="`${sig.txhash}:${sig.outidx}`"
                    class="px-2 py-0.5 rounded-md text-[11px] font-mono bg-[#7695CD]/15 text-[#7695CD] border border-[#7695CD]/30"
                  >
                    ✓ {{ sig.txhash.slice(0, 10) }}...:{{ sig.outidx }}
                  </span>
                </div>
              </div>
            </div>

            <!-- Expandable Raw Transaction Hex Inspector -->
            <details class="group rounded-xl border border-[var(--krista-border)] bg-[var(--krista-surface)] p-3 text-xs">
              <summary class="font-semibold text-[var(--krista-text-muted)] hover:text-[var(--krista-text)] cursor-pointer select-none flex items-center justify-between">
                <span>{{ t('inspectRawTx') }}</span>
                <span class="text-[#7695CD] font-mono text-[11px]">
                  {{ Math.floor((proposal.rawTxHex?.length || 0) / 2) }} bytes
                </span>
              </summary>
              <div class="mt-2.5 space-y-2">
                <div class="terminal-block p-2.5 rounded-lg font-mono text-[11px] break-all max-h-32 overflow-y-auto custom-scroll">
                  {{ proposal.rawTxHex }}
                </div>
                <button
                  type="button"
                  class="text-xs font-semibold text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
                  @click="copyText(proposal.rawTxHex)"
                >
                  {{ t('copyBtn') }} Raw Hex
                </button>
              </div>
            </details>
          </div>

          <!-- Action / Broadcast Status Footer -->
          <div class="pt-3 border-t border-[var(--krista-border)]">
            <!-- Broadcasted Banner -->
            <div
              v-if="proposal.status === 'broadcasted'"
              class="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/35 space-y-1"
            >
              <p class="text-xs font-bold text-emerald-400">
                ✓ {{ t('txBroadcastedTitle') }}
              </p>
              <div class="flex items-center justify-between gap-2">
                <p class="text-[11px] font-mono text-[var(--krista-text-muted)] break-all">
                  TXID: {{ proposal.finalTxid || proposal.broadcastTxId }}
                </p>
                <button
                  v-if="proposal.finalTxid || proposal.broadcastTxId"
                  type="button"
                  class="text-xs font-semibold text-emerald-400 hover:underline shrink-0 cursor-pointer"
                  @click="copyText(proposal.finalTxid || proposal.broadcastTxId || '')"
                >
                  {{ t('copyBtn') }}
                </button>
              </div>
            </div>

            <!-- Voting / Signing Controls -->
            <div v-else class="space-y-3">
              <div
                v-if="proposal.error || proposal.broadcastError"
                role="alert"
                class="p-3 rounded-xl bg-red-500/10 border border-red-500/35 text-xs text-red-400 space-y-1"
              >
                <p class="font-bold">{{ t('broadcastErrorTitle') }}:</p>
                <p class="font-mono text-[11px] break-all">{{ proposal.error || proposal.broadcastError }}</p>
              </div>

              <div class="space-y-1.5">
                <label
                  :for="`select-mn-${proposal.id}`"
                  class="block text-xs font-bold text-[var(--krista-text)]"
                >
                  {{ t('selectMasternodeLabel') }}
                </label>
                <select
                  :id="`select-mn-${proposal.id}`"
                  v-model="selectedNode"
                  class="w-full px-3 py-2 rounded-xl text-xs font-mono bg-[var(--krista-surface)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none focus:border-[#7695CD]"
                >
                  <option value="">{{ t('selectMasternodePlaceholder') }}</option>
                  <option
                    v-for="(node, nIdx) in quorumMembers"
                    :key="getMemberKey(node)"
                    :value="getMemberKey(node)"
                  >
                    #{{ node.rank ?? nIdx + 1 }} — {{ node.ip || node.addr || 'On-Chain MN' }} ({{ node.txhash.slice(0, 12) }}...:{{ node.outidx }})
                  </option>
                </select>
              </div>

              <div class="space-y-1.5">
                <label
                  :for="`wif-proposal-${proposal.id}`"
                  class="block text-xs font-bold text-[var(--krista-text)]"
                >
                  {{ t('wifInputLabel') }}
                </label>
                <input
                  :id="`wif-proposal-${proposal.id}`"
                  v-model="wifKey"
                  :type="showWif ? 'text' : 'password'"
                  autocomplete="off"
                  spellcheck="false"
                  :placeholder="t('wifInputPlaceholder')"
                  class="krista-input w-full px-3 py-2 rounded-xl text-xs font-mono bg-[var(--krista-surface)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none"
                  @input="onWifInput"
                  @blur="onWifBlur"
                />
              </div>

              <p
                v-if="selectedNode && hasNodeSigned(proposal, selectedNode)"
                class="text-xs font-semibold text-emerald-400"
              >
                ✓ {{ t('alreadySignedByYou') }}
              </p>

              <button
                type="button"
                :disabled="
                  isSigning ||
                  (Boolean(selectedNode) && hasNodeSigned(proposal, selectedNode))
                "
                class="w-full py-2.5 px-4 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#7695CD] to-[#F5897C] hover:opacity-95 shadow-sm transition-all cursor-pointer disabled:opacity-50"
                @click="signProposal(proposal)"
              >
                {{ t('signAndVoteBtn') }}
              </button>
            </div>
          </div>
        </article>
      </div>
    </section>

    <!-- CBLSSignedData & H+1 Quorum Security Architecture Guide -->
    <section
      aria-labelledby="arch-guide-heading"
      class="krista-card p-6 sm:p-8 space-y-6 border-t-4 border-t-[#F5897C]"
    >
      <div class="flex items-center gap-3">
        <img
          src="/logo.svg"
          alt="KristaTech"
          width="28"
          height="28"
          class="w-7 h-7 object-contain"
        />
        <h2 id="arch-guide-heading" class="text-lg sm:text-xl font-extrabold text-[var(--krista-text)]">
          {{ t('archModalTitle') }}
        </h2>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-2">
          <h3 class="text-sm font-bold text-[#7695CD]">
            {{ t('archPoint1Title') }}
          </h3>
          <p class="text-xs text-[var(--krista-text-muted)] leading-relaxed">
            {{ t('archPoint1Desc') }}
          </p>
        </div>

        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-2">
          <h3 class="text-sm font-bold text-[#F5897C]">
            {{ t('archPoint2Title') }}
          </h3>
          <p class="text-xs text-[var(--krista-text-muted)] leading-relaxed">
            {{ t('archPoint2Desc') }}
          </p>
        </div>

        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-2">
          <h3 class="text-sm font-bold text-emerald-400">
            {{ t('archPoint3Title') }}
          </h3>
          <p class="text-xs text-[var(--krista-text-muted)] leading-relaxed">
            {{ t('archPoint3Desc') }}
          </p>
        </div>
      </div>
    </section>
  </div>
</template>
