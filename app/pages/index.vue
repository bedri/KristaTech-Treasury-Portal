<template>
  <div class="space-y-8 max-w-6xl mx-auto">
    <!-- Header -->
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
      <div>
        <h1 class="text-3xl font-extrabold tracking-tight text-white sm:text-4xl bg-gradient-to-r from-primary-400 to-indigo-400 bg-clip-text text-transparent">
          KristaTech Hazine Portalı
        </h1>
        <p class="mt-2 text-sm text-slate-400">
          Developer Fund (Hazine) harcamalarını takip edin, aktif quorum üyeliğinizi doğrulayın ve teklifleri tarayıcınızda yerel olarak imzalayın.
        </p>
      </div>
      <div class="flex items-center gap-3">
        <UButton
          to="/admin"
          color="primary"
          icon="i-heroicons-plus-20-solid"
          size="lg"
          class="bg-gradient-to-r from-primary-500 to-indigo-600 hover:from-primary-600 hover:to-indigo-700 shadow-lg shadow-primary-500/20"
        >
          Yeni Teklif Oluştur
        </UButton>
      </div>
    </div>

    <!-- Network Info & Quorum -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Status Card -->
      <UCard class="bg-slate-900/60 border border-slate-800/80 backdrop-blur-md lg:col-span-1">
        <template #header>
          <div class="flex items-center gap-2">
            <UIcon name="i-heroicons-cpu-chip" class="text-primary-400 text-xl" />
            <h3 class="font-bold text-white">Ağ Durumu</h3>
          </div>
        </template>
        
        <div v-if="quorumLoading" class="space-y-3 py-4">
          <USkeleton class="h-4 w-[200px] bg-slate-800" />
          <USkeleton class="h-4 w-[150px] bg-slate-800" />
          <USkeleton class="h-4 w-[250px] bg-slate-800" />
        </div>
        <div v-else-if="quorumData" class="space-y-4 text-sm">
          <div class="flex justify-between border-b border-slate-800/50 pb-2">
            <span class="text-slate-400">Güncel Blok Yüksekliği</span>
            <span class="font-mono text-white font-bold">{{ quorumData.currentHeight }}</span>
          </div>
          <div class="flex justify-between border-b border-slate-800/50 pb-2">
            <span class="text-slate-400">Aktif DKG Yüksekliği</span>
            <span class="font-mono text-white font-bold">{{ quorumData.dkgHeight }}</span>
          </div>
          <div class="flex flex-col gap-1">
            <span class="text-slate-400">Aktif Quorum Seed ({{ quorumData.seedHeight }})</span>
            <span class="font-mono text-xs text-primary-400 break-all bg-slate-950/60 p-2 rounded border border-slate-800">{{ quorumData.seed }}</span>
          </div>
        </div>
      </UCard>

      <!-- Active Quorum Members -->
      <UCard class="bg-slate-900/60 border border-slate-800/80 backdrop-blur-md lg:col-span-2">
        <template #header>
          <div class="flex items-center gap-2">
            <UIcon name="i-heroicons-user-group" class="text-primary-400 text-xl" />
            <h3 class="font-bold text-white">Aktif Quorum Üyeleri (Seçmen Masternode'lar)</h3>
          </div>
        </template>

        <div v-if="quorumLoading" class="space-y-3 py-2">
          <USkeleton class="h-10 w-full bg-slate-800" />
          <USkeleton class="h-10 w-full bg-slate-800" />
          <USkeleton class="h-10 w-full bg-slate-800" />
        </div>
        <div v-else-if="quorumData && quorumData.members" class="overflow-x-auto">
          <table class="w-full text-left border-collapse text-sm">
            <thead>
              <tr class="border-b border-slate-800 text-slate-400">
                <th class="py-2 font-semibold">IP Adresi</th>
                <th class="py-2 font-semibold">Teminat İşlem Hash'i (Collateral)</th>
                <th class="py-2 font-semibold text-right">Durum</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/40">
              <tr v-for="(member, idx) in quorumData.members" :key="idx" class="hover:bg-slate-800/20 transition-colors">
                <td class="py-3 font-mono text-white font-semibold">{{ member.ip }}</td>
                <td class="py-3 font-mono text-xs text-slate-400">{{ member.txhash }}:{{ member.outidx }}</td>
                <td class="py-3 text-right">
                  <UBadge color="primary" variant="subtle" size="xs">SEÇMEN</UBadge>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </UCard>
    </div>

    <!-- Active Proposals -->
    <div class="space-y-4">
      <h2 class="text-2xl font-bold text-white flex items-center gap-2">
        <UIcon name="i-heroicons-document-text" class="text-primary-400" /> Aktif Teklifler ve İmza Durumu
      </h2>

      <div v-if="proposalsLoading" class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <UCard v-for="i in 2" :key="i" class="bg-slate-900/60 border border-slate-800/80">
          <USkeleton class="h-6 w-[200px] bg-slate-800 mb-4" />
          <USkeleton class="h-4 w-full bg-slate-800 mb-2" />
          <USkeleton class="h-4 w-full bg-slate-800" />
        </UCard>
      </div>

      <div v-else-if="proposals.length === 0" class="text-center py-12 bg-slate-900/30 border border-dashed border-slate-800 rounded-xl">
        <UIcon name="i-heroicons-inbox" class="text-5xl text-slate-600 mb-2" />
        <p class="text-slate-400">Şu an aktif veya oylanan bir hazine harcama teklifi bulunmuyor.</p>
      </div>

      <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <UCard
          v-for="proposal in proposals"
          :key="proposal.id"
          class="bg-slate-900/60 border border-slate-800/80 backdrop-blur-md flex flex-col justify-between"
        >
          <div class="space-y-4">
            <div class="flex items-start justify-between">
              <div>
                <span class="text-xs text-slate-400">Harcama Teklifi</span>
                <h3 class="text-xl font-bold text-white mt-1">{{ proposal.amount }} KRISTA</h3>
              </div>
              <UBadge
                :color="proposal.status === 'broadcasted' ? 'green' : proposal.status === 'failed' ? 'red' : 'primary'"
                variant="solid"
              >
                {{ proposal.status === 'broadcasted' ? 'AĞA YAYINLANDI' : proposal.status === 'failed' ? 'BAŞARISIZ' : 'OYLAMADA' }}
              </UBadge>
            </div>

            <div class="text-sm space-y-2 border-t border-slate-800/50 pt-3">
              <div class="flex justify-between">
                <span class="text-slate-400">Hedef Adres</span>
                <span class="font-mono text-white text-xs select-all">{{ proposal.targetAddress }}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-400">İşlem Hash (Message)</span>
                <span class="font-mono text-xs text-primary-400 select-all">{{ proposal.txHash }}</span>
              </div>
            </div>

            <!-- Signatures Progress -->
            <div class="space-y-2">
              <div class="flex justify-between text-xs">
                <span class="text-slate-400 font-semibold">Toplanan Quorum İmzası</span>
                <span class="text-white font-bold">{{ proposal.signatures.length }} / {{ threshold }}</span>
              </div>
              <UProgress :value="proposal.signatures.length" :max="threshold" color="primary" />
            </div>

            <!-- Signed Masternodes List -->
            <div v-if="proposal.signatures.length > 0" class="space-y-1">
              <span class="text-xs text-slate-400 font-semibold">İmzalayan Düğümler:</span>
              <div class="flex flex-wrap gap-1">
                <UBadge
                  v-for="(sig, sIdx) in proposal.signatures"
                  :key="sIdx"
                  color="gray"
                  variant="subtle"
                  size="xs"
                  class="font-mono"
                >
                  {{ sig.txhash.substring(0, 8) }}...:{{ sig.outidx }}
                </UBadge>
              </div>
            </div>
          </div>

          <!-- Signing Action for Voters -->
          <div v-if="proposal.status === 'pending'" class="mt-6 border-t border-slate-800/50 pt-4 space-y-4">
            <div v-if="isUserInQuorum" class="bg-primary-950/20 border border-primary-800/40 rounded-lg p-3 text-xs text-primary-300">
              <div class="flex items-center gap-1 font-bold mb-1">
                <UIcon name="i-heroicons-check-circle-20-solid" /> Tebrikler! Masternode'unuz Aktif Quorum Üyesi
              </div>
              Bu teklifi onaylamak için aşağıya ilgili masternode'un özel anahtarını girerek tarayıcınızda imzalayabilirsiniz.
            </div>

            <div class="flex flex-col gap-2">
              <UFormGroup label="Masternode Seç" size="sm">
                <USelect
                  v-model="signForm.selectedMnIndex"
                  :options="quorumOptions"
                  placeholder="İmza atacak masternode'u seçin"
                  class="bg-slate-950/40"
                />
              </UFormGroup>

              <UFormGroup label="Masternode Private Key (WIF)" size="sm">
                <UInput
                  v-model="signForm.wifKey"
                  type="password"
                  placeholder="Masternode Private Key (örn. 2UNUY2rGp...)"
                  icon="i-heroicons-key"
                  class="bg-slate-950/40"
                />
              </UFormGroup>

              <UButton
                color="primary"
                block
                class="bg-gradient-to-r from-primary-500 to-indigo-600 hover:from-primary-600 hover:to-indigo-700"
                :loading="signingLoading"
                @click="signProposal(proposal)"
              >
                Teklifi Yerel Olarak İmzala ve Oy Ver
              </UButton>
            </div>
          </div>

          <!-- Final transaction info if broadcasted -->
          <div v-if="proposal.status === 'broadcasted'" class="mt-4 border-t border-slate-800/50 pt-3 text-xs text-green-400 space-y-1">
            <div class="font-bold flex items-center gap-1">
              <UIcon name="i-heroicons-check-circle-20-solid" /> İşlem Ağa Yayınlandı!
            </div>
            <div class="break-all font-mono">
              TxID: <span class="select-all text-white font-bold">{{ proposal.finalTxid }}</span>
            </div>
          </div>
          <div v-if="proposal.status === 'failed'" class="mt-4 border-t border-slate-800/50 pt-3 text-xs text-red-400 space-y-1">
            <div class="font-bold flex items-center gap-1">
              <UIcon name="i-heroicons-x-circle-20-solid" /> Yayınlama Hatası
            </div>
            <div class="break-all font-mono text-slate-300">
              {{ proposal.error }}
            </div>
          </div>
        </UCard>
      </div>
    </div>
  </div>
</template>

<script setup>
import elliptic from 'elliptic'

const ec = new elliptic.ec('secp256k1')
const toast = useToast()

const networkState = useState('network', () => 'main')

const quorumData = ref(null)
const quorumLoading = ref(true)

const proposals = ref([])
const proposalsLoading = ref(true)

const threshold = ref(3) // Default to 3/5 majority

const signForm = ref({
  selectedMnIndex: '',
  wifKey: ''
})
const signingLoading = ref(false)

// Fetch Quorum Status
async function fetchQuorum() {
  quorumLoading.value = true
  try {
    const res = await $fetch('/api/quorum')
    if (res.success) {
      quorumData.value = res
      networkState.value = res.chain
      // Majority threshold: 3 for 5-member quorum, 2 for smaller regtest quorum
      threshold.value = (res.members.length < 5) ? 2 : 3
    }
  } catch (err) {
    console.error('Error fetching quorum:', err)
  } finally {
    quorumLoading.value = false
  }
}

// Fetch Proposals
async function fetchProposals() {
  proposalsLoading.value = true
  try {
    const res = await $fetch('/api/proposals')
    proposals.value = res
  } catch (err) {
    console.error('Error fetching proposals:', err)
  } finally {
    proposalsLoading.value = false
  }
}

// Check if user is in quorum
const isUserInQuorum = computed(() => {
  return quorumData.value && quorumData.value.members && quorumData.value.members.length > 0
})

// Quorum options for select
const quorumOptions = computed(() => {
  if (!quorumData.value || !quorumData.value.members) return []
  return quorumData.value.members.map((mn, idx) => ({
    label: `${mn.ip} (${mn.txhash.substring(0, 8)}...:${mn.outidx})`,
    value: idx
  }))
})

// Base58 decoding helper (standard zero-dependency implementation)
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const ALPHABET_MAP = {}
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET[i]] = i
}

function decodeBase58(string) {
  let bytes = [0]
  for (let i = 0; i < string.length; i++) {
    let c = string[i]
    if (!(c in ALPHABET_MAP)) throw new Error('Geçersiz karakter')
    let carry = ALPHABET_MAP[c]
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  for (let i = 0; string[i] === '1' && i < string.length - 1; i++) {
    bytes.push(0)
  }
  return new Uint8Array(bytes.reverse())
}

function getRawPrivateKeyFromWIF(wifString) {
  const decoded = decodeBase58(wifString)
  // wif is: [prefix (1 byte)] [privkey (32 bytes)] [optional compression (1 byte)] [checksum (4 bytes)]
  // We extract the 32-byte private key at index 1 to 33
  const rawKey = decoded.slice(1, 33)
  
  // Convert rawKey bytes to hex string for elliptic
  let hex = ''
  for (let i = 0; i < rawKey.length; i++) {
    hex += rawKey[i].toString(16).padStart(2, '0')
  }
  return hex
}

async function signProposal(proposal) {
  if (signForm.value.selectedMnIndex === '' || !signForm.value.wifKey) {
    toast.add({
      title: 'Eksik Bilgi',
      description: 'Lütfen masternode seçin ve özel anahtarınızı (WIF) girin.',
      color: 'red'
    })
    return
  }

  signingLoading.value = true
  try {
    const selectedMn = quorumData.value.members[signForm.value.selectedMnIndex]
    
    // 1. Decode private key
    let privKeyHex = ''
    try {
      privKeyHex = getRawPrivateKeyFromWIF(signForm.value.wifKey.trim())
    } catch {
      throw new Error('Geçersiz WIF formatı. Lütfen anahtarınızı kontrol edin.')
    }

    // 2. Derive public key and verify it matches the elected masternode public key
    const key = ec.keyFromPrivate(privKeyHex, 'hex')
    const derivedPubHex = key.getPublic(true, 'hex') // Compressed pubkey hex
    
    if (derivedPubHex.toLowerCase() !== selectedMn.pubkey.toLowerCase() &&
        key.getPublic(false, 'hex').toLowerCase() !== selectedMn.pubkey.toLowerCase()) {
      throw new Error('Girdiğiniz özel anahtar seçtiğiniz masternode\'un public key\'i ile eşleşmiyor!')
    }

    // 3. Sign the proposal's txHash
    const signature = key.sign(proposal.txHash)
    const derSigHex = signature.toDER('hex')

    // 4. Send signature to backend
    const response = await $fetch('/api/proposals', {
      method: 'POST',
      body: {
        action: 'sign',
        proposalId: proposal.id,
        txhash: selectedMn.txhash,
        outidx: selectedMn.outidx,
        pubkey: selectedMn.pubkey,
        signature: derSigHex
      }
    })

    if (response.success) {
      toast.add({
        title: 'İmza Başarılı',
        description: 'Teklif başarıyla imzalandı.',
        color: 'green'
      })
      signForm.value.wifKey = ''
      await fetchProposals()
    } else {
      throw new Error(response.error)
    }
  } catch (err) {
    toast.add({
      title: 'İmza Hatası',
      description: err.message || 'İmzalama işlemi başarısız.',
      color: 'red'
    })
  } finally {
    signingLoading.value = false
  }
}

onMounted(() => {
  fetchQuorum()
  fetchProposals()
})
</script>
