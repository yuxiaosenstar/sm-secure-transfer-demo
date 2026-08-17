/**
 * 全项目唯一的国密算法封装(单一事实源)。
 *
 * 纯 ESM 模块,浏览器主线程、Web Worker、Node 服务端与测试全部直接 import:
 *  - 浏览器/Worker:经 Vite 打包,Vue 应用与 module worker 都 `import * as SM from '...'`;
 *  - Node:服务端与测试直接 `import * as SM from '...'`,内部 `import sm from 'sm-crypto'`。
 *
 * 约定(两端必须一致):
 *  - SM4:128 位 key 以 32 位小写 hex 串传递;CBC 模式;每块独立随机 IV(16 字节);
 *    PKCS#7 填充;输入输出均为 Uint8Array(内部转换 sm-crypto 的 Number 数组)。
 *  - SM3:输入 Uint8Array,输出 64 位小写 hex。
 *  - Merkle 根:rootHash = SM3(按序拼接各块 SM3 摘要的原始 32 字节),非 hex 文本拼接。
 *  - SM2:加密/解密 SM4 会话密钥,cipherMode = 1(C1C3C2,GB/T 32918.4 推荐)。
 */
import sm from 'sm-crypto'

const CHUNK_SIZE = 4 * 1024 * 1024 // 4 MiB
const HEX = '0123456789abcdef'

function bytesToHex(u8) {
  let out = ''
  for (let i = 0; i < u8.length; i++) out += HEX[u8[i] >> 4] + HEX[u8[i] & 15]
  return out
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('hex 长度必须为偶数')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

function randBytes(n) {
  const c = (typeof crypto !== 'undefined' ? crypto : globalThis.crypto)
  const out = new Uint8Array(n)
  c.getRandomValues(out)
  return out
}

/** 计算 SM3,输入 Uint8Array,输出 64 位小写 hex */
function sm3Hex(data) {
  return sm.sm3(Array.from(data))
}

/**
 * 加密一个分块。返回 { ivHex, ct(Uint8Array), ptHashHex }。
 * ptHashHex 为明文块的 SM3(完整性校验值,随上传请求头发送)。
 */
function chunkEncrypt(keyHex, plain) {
  const ivHex = bytesToHex(randBytes(16))
  const ct = Uint8Array.from(sm.sm4.encrypt(Array.from(plain), keyHex, {
    mode: 'cbc',
    iv: ivHex,
    padding: 'pkcs#7',
    output: 'array',
  }))
  return { ivHex, ct, ptHashHex: sm3Hex(plain) }
}

/**
 * 解密一个分块。返回 { plain(Uint8Array), ptHashHex }。
 * plainLen 为明文长度(sm-crypto 0.3.9+ 解密自动去 PKCS#7 填充,显式截断兜底,
 * 保证填充字节绝不混入 SM3 摘要)。
 */
function chunkDecrypt(keyHex, ivHex, ct, plainLen) {
  let plain = Uint8Array.from(sm.sm4.decrypt(Array.from(ct), keyHex, {
    mode: 'cbc',
    iv: ivHex,
    padding: 'pkcs#7',
    output: 'array',
  }))
  if (plainLen != null && plain.length > plainLen) plain = plain.subarray(0, plainLen)
  return { plain, ptHashHex: sm3Hex(plain) }
}

/**
 * Merkle 根:SM3(按序拼接各块 32 字节原始摘要)。
 * 文件级完整性锚点,客户端/服务器均可用逐块摘要增量计算。
 */
function merkleRoot(chunkHashHexList) {
  const total = 32 * chunkHashHexList.length
  const concat = new Uint8Array(total)
  for (let i = 0; i < chunkHashHexList.length; i++) {
    concat.set(hexToBytes(chunkHashHexList[i]), i * 32)
  }
  return sm3Hex(concat)
}

/**
 * 密文总长(含 16 字节 IV 前缀):IV + PKCS#7 填充后的密文。
 * 注意:PKCS#7 对明文长度恰为 16 倍数时也要补一整块 0x10,故用 (plainLen + 1)。
 */
function cipherLenOf(plainLen) {
  return 16 + Math.ceil((plainLen + 1) / 16) * 16
}

/** SM2 封装 SM4 会话密钥(16 字节以 hex 串传递,cipherMode=1 C1C3C2) */
function sm2WrapKey(publicKeyHex, sm4KeyHex) {
  return sm.sm2.doEncrypt(sm4KeyHex, publicKeyHex, 1)
}

/** SM2 解封 SM4 会话密钥 */
function sm2UnwrapKey(privateKeyHex, wrappedHex) {
  return sm.sm2.doDecrypt(wrappedHex, privateKeyHex, 1)
}

/** 生成随机 16 字节 SM4 会话密钥(hex 串) */
function generateSessionKey() {
  return bytesToHex(randBytes(16))
}

export {
  CHUNK_SIZE,
  bytesToHex,
  hexToBytes,
  randBytes,
  sm3Hex,
  chunkEncrypt,
  chunkDecrypt,
  merkleRoot,
  cipherLenOf,
  sm2WrapKey,
  sm2UnwrapKey,
  generateSessionKey,
}
