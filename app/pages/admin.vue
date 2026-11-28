<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { useI18n } from '~/composables/useI18n'
import {
  isValidKristaAddress,
  normalizeTaprootAddress,
  calculateTxHash
} from '~/utils/treasuryCrypto'

const { t } = useI18n()
const toast = useToast()
const router = useRouter()
const { data: quorumData } = useFetch<any>('/api/quorum')

const targetAddress = ref('')
const amount = ref<number | string>('')
const rawTxHex = ref('')
const isCreating = ref(false)

const touched = reactive({
  address: false,
  amount: false,
  rawTxHex: false
})

const isAddressValid = computed(() => {
  const clean = targetAddress.value.trim()
  if (!clean) return false
  return isValidKristaAddress(clean)
})

const isAmountValid = computed(() => {
  const num = Number(amount.value)
  return Number.isFinite(num) && num > 0 && num <= 210_000_000
})

const isRawTxHexValid = computed(() => {
  const clean = rawTxHex.value.trim()
  return clean.length >= 20 && clean.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(clean)
})

const addressHasError = computed(() => touched.address && !isAddressValid.value)
const amountHasError = computed(() => touched.amount && !isAmountValid.value)
const rawTxHexHasError = computed(() => touched.rawTxHex && !isRawTxHexValid.value)

function onAddressInput() {
  if (touched.address && isAddressValid.value) {
    touched.address = false
  }
}

function onAmountInput() {
  if (touched.amount && isAmountValid.value) {
    touched.amount = false
  }
}

function onRawTxInput() {
  if (touched.rawTxHex && isRawTxHexValid.value) {
    touched.rawTxHex = false
  }
}

const computedTxHash = computed(() => {
  if (!isRawTxHexValid.value) return ''
  try {
    return calculateTxHash(rawTxHex.value.trim())
  } catch {
    return ''
  }
})

const cliTemplate = computed(() => {
  const addr = isAddressValid.value
    ? normalizeTaprootAddress(targetAddress.value.trim())
    : '<RECIPIENT_KRISTA_ADDRESS>'
  const amt = isAmountValid.value ? Number(amount.value) : '<AMOUNT>'
  const devFundChangeAddr = quorumData.value?.developerFundAddress || '<DEV_FUND_CHANGE_ADDRESS>'
  return [
    '# 1. Create unsigned Raw Transaction spending Developer Fund UTXO:',
    `kristatech-cli createrawtransaction '[{"txid":"<DEV_FUND_UTXO_TXID>","vout":0}]' '{"${addr}":${amt},"${devFundChangeAddr}":<CHANGE_AMOUNT>}'`,
    '',
    '# 2. Sign with the Consensus Treasury Private Key (SIGHASH_ALL):',
    `kristatech-cli signrawtransactionwithkey "<UNSIGNED_HEX>" '["<TREASURY_PRIVATE_KEY_WIF>"]'`
  ].join('\n')
})

async function copyText(value: string) {
  if (!value || typeof navigator === 'undefined' || !navigator.clipboard) return
  try {
    await navigator.clipboard.writeText(value)
    toast.add({
      title: t('copiedToast'),
      color: 'success'
    })
  } catch {
    // Ignore clipboard error
  }
}

async function createProposal() {
  touched.address = true
  touched.amount = true
  touched.rawTxHex = true

  if (!isAddressValid.value || !isAmountValid.value || !isRawTxHexValid.value) {
    toast.add({
      title: t('toastMissingTitle'),
      description: t('toastMissingCreateDesc'),
      color: 'warning'
    })
    return
  }

  isCreating.value = true
  try {
    const cleanHex = rawTxHex.value.trim()
    const txHash = calculateTxHash(cleanHex)
    const normalizedAddr = normalizeTaprootAddress(targetAddress.value.trim())

    const res = await $fetch<{ success: boolean; error?: string }>('/api/proposals', {
      method: 'POST',
      body: {
        action: 'create',
        rawTxHex: cleanHex,
        txHash,
        targetAddress: normalizedAddr,
        amount: Number(amount.value)
      }
    })

    if (!res?.success) {
      throw new Error(res?.error || t('toastCreateErrorTitle'))
    }

    toast.add({
      title: t('toastCreateSuccessTitle'),
      description: t('toastCreateSuccessDesc'),
      color: 'success'
    })

    router.push('/')
  } catch (err: unknown) {
    const fetchErr = err as { data?: { statusMessage?: string; error?: string }; message?: string }
    const errMsg =
      fetchErr?.data?.error || fetchErr?.data?.statusMessage || fetchErr?.message || String(err)
    toast.add({
      title: t('toastCreateErrorTitle'),
      description: errMsg,
      color: 'error'
    })
  } finally {
    isCreating.value = false
  }
}
</script>

<template>
  <div class="max-w-4xl mx-auto space-y-8">
    <!-- Top Back Link -->
    <div>
      <NuxtLink
        to="/"
        class="inline-flex items-center gap-2 text-xs font-bold text-[#7695CD] hover:text-[#F5897C] transition-colors"
      >
        <svg
          aria-hidden="true"
          class="w-4 h-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path stroke-linecap="round" stroke-linejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
        </svg>
        <span>{{ t('backToPortal') }}</span>
      </NuxtLink>
    </div>

    <!-- Header Card -->
    <section class="krista-card krista-hero-glow p-6 sm:p-8 space-y-6">
      <div class="flex items-start gap-4">
        <div
          class="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#7695CD]/20 to-[#F5897C]/20 border border-[#F5897C]/40 flex items-center justify-center shrink-0"
        >
          <img
            src="/logo.svg"
            alt="KristaTech"
            width="28"
            height="28"
            class="w-7 h-7 object-contain"
          />
        </div>
        <div class="space-y-1.5">
          <h1 class="text-2xl sm:text-3xl font-extrabold tracking-tight text-[var(--krista-text)]">
            {{ t('adminTitle') }}
          </h1>
          <p class="text-sm text-[var(--krista-text-muted)] leading-relaxed">
            {{ t('adminSubtitle') }}
          </p>
        </div>
      </div>

      <!-- 3-Step Workflow Strip -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1">
          <h2 class="text-xs font-extrabold uppercase tracking-wider text-[#7695CD]">
            {{ t('step1Title') }}
          </h2>
          <p class="text-xs text-[var(--krista-text-muted)]">
            {{ t('step1Desc') }}
          </p>
        </div>

        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1">
          <h2 class="text-xs font-extrabold uppercase tracking-wider text-[#F5897C]">
            {{ t('step2Title') }}
          </h2>
          <p class="text-xs text-[var(--krista-text-muted)]">
            {{ t('step2Desc') }}
          </p>
        </div>

        <div class="p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1">
          <h2 class="text-xs font-extrabold uppercase tracking-wider text-emerald-400">
            {{ t('step3Title') }}
          </h2>
          <p class="text-xs text-[var(--krista-text-muted)]">
            {{ t('step3Desc') }}
          </p>
        </div>
      </div>
    </section>

    <!-- Early Governance Activation Notice -->
    <div
      v-if="quorumData?.success && quorumData.treasuryGovernanceStartHeight && quorumData.treasuryGovernanceActive === false"
      role="status"
      class="rounded-2xl border border-amber-500/35 bg-amber-500/10 p-4 flex items-start gap-3 text-sm"
    >
      <svg aria-hidden="true" class="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
      <div class="space-y-1">
        <div class="flex flex-wrap items-center gap-2">
          <p class="font-bold text-amber-600 dark:text-amber-400">
            {{ t('governanceEarlyNoticeTitle') }}
          </p>
          <span class="text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-600 dark:text-amber-300 border border-amber-500/30">
            #{{ quorumData.currentHeight }} / #{{ quorumData.treasuryGovernanceStartHeight }}
          </span>
        </div>
        <p class="text-xs text-[var(--krista-text-muted)] leading-relaxed">
          {{ t('governanceEarlyNoticeDesc') }}
        </p>
      </div>
    </div>

    <!-- Proposal Creation Form -->
    <form
      novalidate
      class="krista-card p-6 sm:p-8 space-y-6"
      @submit.prevent="createProposal"
    >
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Target Recipient KRISTA Address -->
        <div
          class="krista-field-group p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1.5"
        >
          <label
            for="proposal-target-address"
            class="block text-xs font-bold uppercase tracking-wider text-[var(--krista-text)]"
          >
            {{ t('targetAddressLabel') }} *
          </label>
          <!-- Format hint placed ABOVE input so autocomplete popovers do not cover it -->
          <p id="target-address-hint" class="text-xs text-[var(--krista-text-muted)]">
            {{ t('targetAddressHint') }}
          </p>
          <input
            id="proposal-target-address"
            v-model="targetAddress"
            type="text"
            required
            autocomplete="off"
            autocorrect="off"
            autocapitalize="none"
            spellcheck="false"
            placeholder="KT... / kt1p... / kt..."
            aria-describedby="target-address-hint target-address-error"
            :aria-invalid="addressHasError ? 'true' : undefined"
            class="krista-input w-full px-3.5 py-2.5 rounded-xl text-sm font-mono bg-[var(--krista-bg-elevated)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none"
            @input="onAddressInput"
            @blur="touched.address = true"
          />
          <p
            v-if="addressHasError"
            id="target-address-error"
            role="alert"
            class="text-xs font-semibold text-red-400 pt-1"
          >
            {{ t('targetAddressError') }}
          </p>
        </div>

        <!-- Spend Amount (KRISTA) -->
        <div
          class="krista-field-group p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1.5"
        >
          <label
            for="proposal-amount"
            class="block text-xs font-bold uppercase tracking-wider text-[var(--krista-text)]"
          >
            {{ t('amountLabel') }} *
          </label>
          <!-- Format hint placed ABOVE input -->
          <p id="proposal-amount-hint" class="text-xs text-[var(--krista-text-muted)]">
            {{ t('amountHint') }}
          </p>
          <input
            id="proposal-amount"
            v-model="amount"
            type="number"
            step="any"
            min="0.00000001"
            max="210000000"
            required
            placeholder="250.00"
            aria-describedby="proposal-amount-hint proposal-amount-error"
            :aria-invalid="amountHasError ? 'true' : undefined"
            class="krista-input w-full px-3.5 py-2.5 rounded-xl text-sm font-mono bg-[var(--krista-bg-elevated)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none"
            @input="onAmountInput"
            @blur="touched.amount = true"
          />
          <p
            v-if="amountHasError"
            id="proposal-amount-error"
            role="alert"
            class="text-xs font-semibold text-red-400 pt-1"
          >
            {{ t('amountError') }}
          </p>
        </div>
      </div>

      <!-- Treasury-Signed Raw Transaction Hex -->
      <div
        class="krista-field-group p-4 rounded-xl bg-[var(--krista-surface)] border border-[var(--krista-border)] space-y-1.5"
      >
        <label
          for="proposal-raw-tx-hex"
          class="block text-xs font-bold uppercase tracking-wider text-[var(--krista-text)]"
        >
          {{ t('rawTxHexLabel') }} *
        </label>
        <!-- Format hint placed ABOVE textarea -->
        <p id="raw-tx-hex-hint" class="text-xs text-[var(--krista-text-muted)]">
          {{ t('rawTxHexHint') }}
        </p>
        <textarea
          id="proposal-raw-tx-hex"
          v-model="rawTxHex"
          rows="6"
          required
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          placeholder="0200000001..."
          aria-describedby="raw-tx-hex-hint raw-tx-hex-error"
          :aria-invalid="rawTxHexHasError ? 'true' : undefined"
          class="krista-input w-full p-3.5 rounded-xl text-xs font-mono bg-[var(--krista-bg-elevated)] text-[var(--krista-text)] border border-[var(--krista-border)] focus:outline-none custom-scroll"
          @input="onRawTxInput"
          @blur="touched.rawTxHex = true"
        ></textarea>
        <p
          v-if="rawTxHexHasError"
          id="raw-tx-hex-error"
          role="alert"
          class="text-xs font-semibold text-red-400 pt-1"
        >
          {{ t('rawTxHexError') }}
        </p>
      </div>

      <!-- Live Computed Double-SHA256 txHash Preview -->
      <div
        v-if="computedTxHash"
        class="p-4 rounded-xl bg-[#7695CD]/10 border border-[#7695CD]/35 space-y-1.5"
      >
        <div class="flex items-center justify-between text-xs">
          <span class="font-bold text-[#7695CD]">
            {{ t('computedTxHashLabel') }}
          </span>
          <button
            type="button"
            class="font-semibold text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
            @click="copyText(computedTxHash)"
          >
            {{ t('copyBtn') }}
          </button>
        </div>
        <p class="font-mono text-xs text-[var(--krista-text)] break-all">
          {{ computedTxHash }}
        </p>
      </div>

      <!-- Interactive kristatech-cli Helper -->
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-[var(--krista-text-muted)]">
            {{ t('cliHelperTitle') }}
          </span>
          <button
            type="button"
            class="text-xs font-semibold text-[#7695CD] hover:text-[#F5897C] cursor-pointer"
            @click="copyText(cliTemplate)"
          >
            {{ t('copyBtn') }}
          </button>
        </div>
        <pre
          class="terminal-block p-4 rounded-xl font-mono text-xs overflow-x-auto custom-scroll leading-relaxed"
        >{{ cliTemplate }}</pre>
      </div>

      <!-- Submit & Cancel Actions -->
      <div class="flex items-center justify-end gap-3 pt-4 border-t border-[var(--krista-border)]">
        <NuxtLink
          to="/"
          class="px-5 py-2.5 rounded-xl text-xs font-bold border border-[var(--krista-border)] bg-[var(--krista-surface)] text-[var(--krista-text)] hover:border-[#7695CD] transition-colors"
        >
          {{ t('cancelBtn') }}
        </NuxtLink>

        <button
          type="submit"
          :disabled="isCreating"
          class="px-6 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#7695CD] to-[#F5897C] hover:opacity-95 shadow-md transition-all cursor-pointer disabled:opacity-50"
        >
          {{ t('publishProposalBtn') }}
        </button>
      </div>
    </form>
  </div>
</template>
