// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2024-11-01',
  devtools: { enabled: true },

  icon: {
    clientBundle: {
      sizeLimitKb: 512 // Increase limit to 512KB (default is 256KB)
    }
  },

  modules: ['nuxt-studio']
})