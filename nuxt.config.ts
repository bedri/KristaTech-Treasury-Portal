import { SECURITY_HEADERS } from './server/utils/security'

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  future: {
    compatibilityVersion: 4
  },
  modules: ['@nuxt/ui'],
  css: ['~/assets/css/main.css'],
  compatibilityDate: '2025-07-15',
  devtools: { enabled: process.env.NODE_ENV !== 'production' },
  app: {
    head: {
      link: [
        { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
        { rel: 'alternate icon', type: 'image/x-icon', href: '/favicon.ico?v=2' }
      ]
    }
  },
  routeRules: {
    '/**': {
      headers: { ...SECURITY_HEADERS }
    }
  },
  devServer: {
    host: '127.0.0.1'
  }
})
