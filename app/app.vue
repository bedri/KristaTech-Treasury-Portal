<script setup lang="ts">
import { useI18n } from '~/composables/useI18n'

const { locale, t } = useI18n()

useHead({
  title: computed(() => t('brandTitle')),
  htmlAttrs: {
    lang: computed(() => locale.value)
  },
  meta: [
    { name: 'color-scheme', content: 'light dark' },
    { name: 'theme-color', content: '#7695CD' },
    { name: 'description', content: computed(() => t('heroDescription')) }
  ]
})
</script>

<template>
  <UApp>
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
  </UApp>
</template>
