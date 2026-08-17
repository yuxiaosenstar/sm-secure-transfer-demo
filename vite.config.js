import { defineConfig } from 'vite'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  resolve: {
    alias: {
      // Vue full build(含运行时编译器):index.html 的内联模板在运行时编译
      vue: 'vue/dist/vue.esm-bundler.js',
      // sm-crypto 的 rng.js 里有防御性 require('crypto'),浏览器打包时指向 globalThis.crypto
      crypto: fileURLToPath(new URL('./web/shims/node-crypto-stub.js', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    target: 'es2022',
  },
})
