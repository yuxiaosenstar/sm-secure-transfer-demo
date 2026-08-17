/**
 * 服务端加解密快路径。
 *
 * Node 24 原生支持 sm4-cbc 与 sm3(本机实测 getCiphers/getHashes 均有),吞吐
 * 比 sm-crypto 纯 JS 高约两个数量级。两端实现字节级兼容(e2e 互操作 KAT 保障),
 * 不支持原生时自动回退 shared/crypto.js 纯 JS 实现。
 */
import crypto from 'node:crypto'
import * as shared from '../web/shared/crypto.js'

const HAS_NATIVE = crypto.getCiphers().includes('sm4-cbc') && crypto.getHashes().includes('sm3')

/** SM4-CBC 解密(key/iv 为 32 位 hex),返回去除 PKCS#7 填充后的明文 Buffer */
function sm4Decrypt(keyHex, ivHex, ct) {
  if (HAS_NATIVE) {
    const decipher = crypto.createDecipheriv(
      'sm4-cbc',
      Buffer.from(keyHex, 'hex'),
      Buffer.from(ivHex, 'hex')
    )
    return Buffer.concat([decipher.update(ct), decipher.final()])
  }
  const { plain } = shared.chunkDecrypt(keyHex, ivHex, new Uint8Array(ct), ct.length)
  return Buffer.from(plain)
}

/** SM3 摘要,返回 64 位小写 hex */
function sm3Hex(buf) {
  if (HAS_NATIVE) return crypto.createHash('sm3').update(buf).digest('hex')
  return shared.sm3Hex(new Uint8Array(buf)) // 回退:与浏览器端同一份纯 JS 实现
}

export { HAS_NATIVE, sm4Decrypt, sm3Hex }
