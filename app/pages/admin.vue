<template>
  <div class="space-y-8 max-w-4xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-slate-800 pb-6">
      <div>
        <NuxtLink to="/" class="text-sm text-primary-400 hover:text-primary-300 flex items-center gap-1 mb-2 transition-colors">
          <UIcon name="i-heroicons-arrow-left-20-solid" /> Portal Ana Sayfasına Dön
        </NuxtLink>
        <h1 class="text-3xl font-extrabold tracking-tight text-white sm:text-4xl bg-gradient-to-r from-primary-400 to-indigo-400 bg-clip-text text-transparent">
          Yeni Harcama Teklifi (Proposal)
        </h1>
        <p class="mt-2 text-sm text-slate-400">
          Developer Fund (Hazine) UTXO'sunu harcamak için raw transaction oluşturun ve Spork anahtarınız ile imzalayarak portalda oylamaya sunun.
        </p>
      </div>
    </div>

    <!-- Form Card -->
    <UCard class="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 shadow-2xl relative overflow-hidden">
      <!-- Glow effect -->
      <div class="absolute -top-40 -right-40 w-80 h-80 bg-primary-500/10 rounded-full blur-3xl pointer-events-none"></div>

      <div class="space-y-6">
        <!-- Target Address -->
        <UFormGroup label="Hedef (Alıcı) Adresi" name="target" required>
          <UInput
            v-model="form.targetAddress"
            placeholder="KTQHBaf7EboM61rAgJx9xV93uhoAhgP9Z6t"
            icon="i-heroicons-wallet"
            color="primary"
            variant="outlined"
            size="lg"
            class="bg-slate-950/40"
          />
        </UFormGroup>

        <!-- Amount -->
        <UFormGroup label="Miktar (KRISTA)" name="amount" required>
          <UInput
            v-model="form.amount"
            type="number"
            step="0.00000001"
            placeholder="100.0"
            icon="i-heroicons-currency-dollar"
            color="primary"
            variant="outlined"
            size="lg"
            class="bg-slate-950/40"
          />
        </UFormGroup>

        <!-- Raw TX Hex -->
        <UFormGroup label="Spork Key ile İmzalanmış Raw Transaction Hex" name="rawTx" required>
          <UTextarea
            v-model="form.rawTxHex"
            placeholder="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff..."
            :rows="6"
            color="primary"
            variant="outlined"
            size="lg"
            class="font-mono bg-slate-950/40"
          />
        </UFormGroup>

        <!-- Action Button -->
        <div class="flex justify-end gap-3 pt-4 border-t border-slate-800/60">
          <UButton
            color="gray"
            variant="ghost"
            to="/"
            size="lg"
          >
            İptal
          </UButton>
          <UButton
            color="primary"
            size="lg"
            :loading="loading"
            class="px-6 bg-gradient-to-r from-primary-500 to-indigo-600 hover:from-primary-600 hover:to-indigo-700 shadow-lg shadow-primary-500/20 transition-all duration-300"
            @click="createProposal"
          >
            Teklifi Yayınla
          </UButton>
        </div>
      </div>
    </UCard>
  </div>
</template>

<script setup>
import { sha256 } from '@noble/hashes/sha256'

const router = useRouter()
const toast = useToast()

const form = ref({
  targetAddress: '',
  amount: '',
  rawTxHex: ''
})

const loading = ref(false)

// Helper to double-sha256 in hex format (little-endian representation of hash)
function calculateTxHash(rawTxHex) {
  const clean = rawTxHex.trim()
  const rawBytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < rawBytes.length; i++) {
    rawBytes[i] = parseInt(clean.substr(i * 2, 2), 16)
  }
  const h2 = sha256(sha256(rawBytes))
  const rev = Array.from(h2).reverse()
  return rev.map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function createProposal() {
  if (!form.value.targetAddress || !form.value.amount || !form.value.rawTxHex) {
    toast.add({
      title: 'Eksik Bilgi',
      description: 'Lütfen tüm alanları doldurun.',
      color: 'red'
    })
    return
  }

  loading.value = true
  try {
    const txHash = calculateTxHash(form.value.rawTxHex)

    const response = await $fetch('/api/proposals', {
      method: 'POST',
      body: {
        action: 'create',
        rawTxHex: form.value.rawTxHex.trim(),
        txHash,
        targetAddress: form.value.targetAddress.trim(),
        amount: parseFloat(form.value.amount)
      }
    })

    if (response.success) {
      toast.add({
        title: 'Başarılı',
        description: 'Teklif başarıyla oluşturuldu ve oylamaya sunuldu.',
        color: 'green'
      })
      router.push('/')
    } else {
      throw new Error(response.error)
    }
  } catch (err) {
    toast.add({
      title: 'Hata',
      description: err.message || 'Teklif oluşturulurken bir hata oluştu.',
      color: 'red'
    })
  } finally {
    loading.value = false
  }
}
</script>
