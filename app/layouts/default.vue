<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useI18n, sanitizeTheme } from '~/composables/useI18n'

const { locale, languages, setLocale, initLocaleFromStorage, t } = useI18n()
const colorMode = useColorMode()
const route = useRoute()

const isDark = computed(() => colorMode.value !== 'light')

function toggleTheme() {
  const next = isDark.value ? 'light' : 'dark'
  colorMode.preference = next
  if (typeof window !== 'undefined') {
    try {
      window.localStorage.setItem('krista_treasury_theme', next)
      document.documentElement.classList.toggle('dark', next === 'dark')
      document.documentElement.classList.toggle('light', next === 'light')
    } catch {
      // Ignore storage restrictions
    }
  }
}

function onLanguageSelectChange(event: Event) {
  const target = event.target as HTMLSelectElement | null
  if (target?.value) {
    setLocale(target.value)
  }
}

onMounted(() => {
  initLocaleFromStorage()
  if (typeof window !== 'undefined') {
    try {
      const savedTheme = window.localStorage.getItem('krista_treasury_theme')
      if (savedTheme) {
        const cleanTheme = sanitizeTheme(savedTheme, 'dark')
        colorMode.preference = cleanTheme
        document.documentElement.classList.toggle('dark', cleanTheme === 'dark')
        document.documentElement.classList.toggle('light', cleanTheme === 'light')
      }
    } catch {
      // Ignore storage errors
    }
  }
})
</script>

<template>
  <div class="min-h-screen flex flex-col selection:bg-[#7695CD]/30 selection:text-[#F5897C]">
    <!-- Accessible Skip Link -->
    <a href="#main-content" class="skip-link visually-hidden">
      {{ t('skipToContent') }}
    </a>

    <!-- Top Brand Accent Bar (#7695CD -> #F5897C) -->
    <div class="brand-accent-bar" aria-hidden="true"></div>

    <!-- Institutional Header -->
    <header
      class="sticky top-0 z-40 backdrop-blur-xl bg-[var(--krista-bg-elevated)]/90 border-b border-[var(--krista-border)] transition-colors"
    >
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between gap-4">
        <!-- Brand Identity & Official KristaTech Logo -->
        <NuxtLink
          to="/"
          class="flex items-center gap-3.5 group focus:outline-none rounded-xl p-1 -ml-1"
        >
          <div
            class="relative w-11 h-11 rounded-xl bg-gradient-to-br from-[#7695CD]/15 via-[#7695CD]/5 to-[#F5897C]/15 border border-[#7695CD]/35 flex items-center justify-center shadow-sm group-hover:border-[#F5897C]/60 transition-all"
          >
            <img
              src="/logo.svg"
              alt="KristaTech Logo"
              width="32"
              height="32"
              class="w-8 h-8 object-contain transition-transform duration-200 group-hover:scale-105"
            />
          </div>
          <div class="flex flex-col">
            <div class="flex items-center gap-2">
              <span class="font-extrabold text-lg tracking-tight text-[var(--krista-text)]">
                Krista<span class="text-[#7695CD]">Tech</span>
              </span>
              <span
                class="text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-[#F5897C]/15 text-[#F5897C] border border-[#F5897C]/35"
              >
                {{ t('badgeTreasury') }}
              </span>
            </div>
            <span class="text-xs text-[var(--krista-text-muted)] hidden sm:inline">
              {{ t('brandSubtitle') }}
            </span>
          </div>
        </NuxtLink>

        <!-- Primary Navigation & Global Controls -->
        <div class="flex items-center gap-2 sm:gap-3">
          <nav aria-label="Primary Navigation" class="hidden md:flex items-center gap-1.5 mr-2">
            <NuxtLink
              to="/"
              class="px-3.5 py-2 rounded-xl text-sm font-semibold transition-all flex items-center gap-2"
              :class="
                route.path === '/'
                  ? 'bg-[#7695CD]/15 text-[#7695CD] border border-[#7695CD]/35 shadow-xs'
                  : 'text-[var(--krista-text-muted)] hover:text-[var(--krista-text)] hover:bg-[#7695CD]/10'
              "
            >
              <svg
                aria-hidden="true"
                class="w-4 h-4 text-[#7695CD]"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              <span>{{ t('navProposals') }}</span>
            </NuxtLink>

            <NuxtLink
              to="/admin"
              class="px-3.5 py-2 rounded-xl text-sm font-semibold transition-all flex items-center gap-2"
              :class="
                route.path === '/admin'
                  ? 'bg-[#F5897C]/15 text-[#F5897C] border border-[#F5897C]/40 shadow-xs'
                  : 'text-[var(--krista-text-muted)] hover:text-[var(--krista-text)] hover:bg-[#F5897C]/10'
              "
            >
              <svg
                aria-hidden="true"
                class="w-4 h-4 text-[#F5897C]"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2"
              >
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              <span>{{ t('navCreateProposal') }}</span>
            </NuxtLink>
          </nav>

          <!-- Quick TR / EN Switcher + 10-Language Selector -->
          <div
            class="flex items-center rounded-xl border border-[var(--krista-border)] bg-[var(--krista-surface)] p-0.5"
          >
            <button
              type="button"
              class="px-2.5 py-1 text-xs font-bold rounded-lg transition-colors cursor-pointer"
              :class="
                locale === 'tr'
                  ? 'bg-[#7695CD] text-white shadow-xs'
                  : 'text-[var(--krista-text-muted)] hover:text-[var(--krista-text)]'
              "
              :aria-pressed="locale === 'tr'"
              @click="setLocale('tr')"
            >
              TR
            </button>
            <button
              type="button"
              class="px-2.5 py-1 text-xs font-bold rounded-lg transition-colors cursor-pointer"
              :class="
                locale === 'en'
                  ? 'bg-[#7695CD] text-white shadow-xs'
                  : 'text-[var(--krista-text-muted)] hover:text-[var(--krista-text)]'
              "
              :aria-pressed="locale === 'en'"
              @click="setLocale('en')"
            >
              EN
            </button>
            <label for="global-language-select" class="visually-hidden">
              {{ t('selectLanguage') }}
            </label>
            <select
              id="global-language-select"
              :value="locale"
              :aria-label="t('selectLanguage')"
              class="bg-transparent text-xs font-semibold text-[var(--krista-text)] pl-1.5 pr-2 py-1 rounded-lg focus:outline-none cursor-pointer border-l border-[var(--krista-border)] ml-0.5"
              @change="onLanguageSelectChange"
            >
              <option
                v-for="lang in languages"
                :key="lang.code"
                :value="lang.code"
                class="bg-[var(--krista-bg-elevated)] text-[var(--krista-text)]"
              >
                {{ lang.flag }} {{ lang.code.toUpperCase() }} — {{ lang.name }}
              </option>
            </select>
          </div>

          <!-- Theme Switcher Button -->
          <button
            type="button"
            :aria-label="isDark ? t('themeSwitchLight') : t('themeSwitchDark')"
            :title="isDark ? t('themeSwitchLight') : t('themeSwitchDark')"
            class="p-2.5 rounded-xl border border-[var(--krista-border)] bg-[var(--krista-surface)] text-[var(--krista-text)] hover:border-[#7695CD] transition-colors cursor-pointer"
            @click="toggleTheme"
          >
            <svg
              v-if="isDark"
              aria-hidden="true"
              class="w-4 h-4 text-[#F5897C]"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
            <svg
              v-else
              aria-hidden="true"
              class="w-4 h-4 text-[#7695CD]"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
              />
            </svg>
          </button>
        </div>
      </div>

      <!-- Mobile Sub-navigation -->
      <div
        class="md:hidden border-t border-[var(--krista-border)] px-4 py-2 flex items-center justify-around bg-[var(--krista-bg-elevated)]/95"
      >
        <NuxtLink
          to="/"
          class="text-xs font-semibold px-3 py-1.5 rounded-lg"
          :class="route.path === '/' ? 'bg-[#7695CD]/20 text-[#7695CD]' : 'text-[var(--krista-text-muted)]'"
        >
          {{ t('navProposals') }}
        </NuxtLink>
        <NuxtLink
          to="/admin"
          class="text-xs font-semibold px-3 py-1.5 rounded-lg"
          :class="route.path === '/admin' ? 'bg-[#F5897C]/20 text-[#F5897C]' : 'text-[var(--krista-text-muted)]'"
        >
          + {{ t('navCreateProposal') }}
        </NuxtLink>
      </div>
    </header>

    <!-- Focusable Main Content Landmark -->
    <main
      id="main-content"
      tabindex="-1"
      class="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 focus:outline-none"
    >
      <slot />
    </main>

    <!-- Institutional Footer -->
    <footer class="border-t border-[var(--krista-border)] bg-[var(--krista-bg-elevated)]/80 py-8 mt-16">
      <div
        class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[var(--krista-text-muted)]"
      >
        <div class="flex items-center gap-3">
          <img
            src="/logo.svg"
            alt="KristaTech"
            width="24"
            height="24"
            class="w-6 h-6 object-contain"
          />
          <span>
            &copy; {{ new Date().getFullYear() }} {{ t('footerRights') }}
          </span>
        </div>

        <div class="flex flex-wrap items-center gap-4">
          <span class="inline-flex items-center gap-1.5 font-mono text-[11px] text-[#7695CD]">
            <span class="w-2 h-2 rounded-full bg-[#7695CD]"></span>
            Core v1.5.9.0 &bull; Proto 70983 &bull; KTDIP3 &amp; Fairness &bull; BLS12-381
          </span>
          <a
            href="https://krista.kristalteknoloji.com"
            target="_blank"
            rel="noopener noreferrer"
            class="hover:text-[#7695CD] transition-colors font-medium"
          >
            Website
          </a>
          <a
            href="https://explorer.kristalteknoloji.com"
            target="_blank"
            rel="noopener noreferrer"
            class="hover:text-[#7695CD] transition-colors font-medium"
          >
            Explorer
          </a>
          <a
            href="https://github.com/bedri/KristaTech-KRISTA"
            target="_blank"
            rel="noopener noreferrer"
            class="hover:text-[#F5897C] transition-colors font-medium"
          >
            Krista Core
          </a>
        </div>
      </div>
    </footer>
  </div>
</template>
