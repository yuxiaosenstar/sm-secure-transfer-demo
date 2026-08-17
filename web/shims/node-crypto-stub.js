/**
 * sm-crypto 的 src/sm2/rng.js 里有一处防御性 `require('crypto')`(仅 Node 环境取
 * 随机源;浏览器主线程走 window.crypto 分支,Worker 里 window 未定义会走 require
 * 分支)。Vite 浏览器打包时把 `crypto` alias 到本模块。
 *
 * 注意:esbuild 预打包会把 ESM namespace 经 __toCommonJS 转成 { default, ... } 形态,
 * rng.js 调用的是 nodeCrypto.getRandomValues —— 因此除 default 外必须把 getRandomValues
 * 也作为命名导出,两种形态下调用方都能取到。
 */
const g = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : {}
export default g
export const getRandomValues = g.getRandomValues ? g.getRandomValues.bind(g) : () => {
  throw new Error('当前环境不支持 crypto.getRandomValues')
}
