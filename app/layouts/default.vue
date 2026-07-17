<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col relative font-sans antialiased selection:bg-primary-500 selection:text-white overflow-x-hidden">
    <!-- Grid Overlay Background -->
    <div class="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-30 pointer-events-none"></div>

    <!-- Radiant Glow Spots -->
    <div class="absolute top-0 left-1/4 -translate-x-1/2 w-96 h-96 bg-primary-500/10 rounded-full blur-3xl pointer-events-none"></div>
    <div class="absolute top-1/3 right-1/4 translate-x-1/2 w-[30rem] h-[30rem] bg-indigo-500/5 rounded-full blur-3xl pointer-events-none"></div>

    <!-- Navigation Header -->
    <header class="sticky top-0 z-40 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/60">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <!-- Premium Logo Badge -->
          <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-primary-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <span class="text-white font-extrabold text-lg select-none">K</span>
          </div>
          <div>
            <span class="font-extrabold tracking-tight text-white">KRISTA</span>
            <span class="text-xs text-primary-400 font-semibold ml-1.5 uppercase tracking-widest bg-primary-950/80 border border-primary-800/40 px-1.5 py-0.5 rounded-md">TREASURY</span>
          </div>
        </div>

        <div class="flex items-center gap-4 text-sm font-semibold text-slate-400">
          <NuxtLink to="/" class="hover:text-white transition-colors" active-class="text-white">
            Teklifler
          </NuxtLink>
          <NuxtLink to="/admin" class="hover:text-white transition-colors" active-class="text-white">
            Yönetim
          </NuxtLink>
          <span class="text-slate-700">|</span>
          <span class="flex items-center gap-1.5 text-xs text-green-400 bg-green-950/40 border border-green-800/30 px-2.5 py-1 rounded-full">
            <span class="w-1.5 h-1.5 bg-green-400 rounded-full animate-ping"></span>
            Testnet Bağlı
          </span>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10 relative z-10">
      <slot />
    </main>

    <!-- Footer -->
    <footer class="border-t border-slate-900 bg-slate-950/60 py-6 text-center text-xs text-slate-500 relative z-10">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          © 2026 KristaTech Developers. Tüm hakları saklıdır.
        </div>
        <div class="flex items-center gap-4">
          <a href="https://github.com/Coin-Projects/KristaTech-KRISTA" target="_blank" class="hover:text-slate-300 transition-colors">GitHub</a>
          <span>•</span>
          <span class="text-slate-600">v1.0.0</span>
        </div>
      </div>
    </footer>
  </div>
</template>
