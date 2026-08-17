/**
 * 上传会话:管理 SM4 会话密钥。
 *
 * 客户端每次上传携带 SM2 封装的随机 SM4 密钥(init 时解封)。服务器只把密钥
 * 驻留内存用于分块校验,meta.json 只持久化 SM2 封装形态 —— 明文密钥永不落盘。
 * 服务重启后可从 meta.wrappedKey + 私钥重新解封(惰性重水化)。
 */
import { sm2 } from 'sm-crypto'
import * as store from './store.js'

const cache = new Map() // uploadId -> SM4 key(32 hex),仅驻留内存

/**
 * 解封 SM2 封装的 SM4 会话密钥并校验长度(16 字节)。
 * 入口处先验 wrappedKey 的 hex 形态:SM2 密文(C1C3C2)约 96–98 字节 hex,
 * 格式非法直接拒绝,避免把任意字符串喂进 doDecrypt 触发解析异常或放大攻击面。
 */
function unwrapKey(wrappedKeyHex) {
  if (typeof wrappedKeyHex !== 'string' || !/^[0-9a-f]{200,400}$/i.test(wrappedKeyHex)) {
    throw new Error('wrappedKey 格式非法')
  }
  const kp = store.ensureKeypair()
  let keyHex
  try {
    keyHex = sm2.doDecrypt(wrappedKeyHex, kp.privateKey, 1)
  } catch (e) {
    throw new Error('SM2 解封失败')
  }
  if (!/^[0-9a-f]{32}$/i.test(keyHex)) throw new Error('解封后的 SM4 密钥长度非法')
  return keyHex.toLowerCase()
}

function openSession(id, wrappedKeyHex) {
  const keyHex = unwrapKey(wrappedKeyHex)
  cache.set(id, keyHex)
  return keyHex
}

/** 取会话密钥;内存 miss 时从 meta 的封装密钥重解封(重启恢复场景) */
function getSession(id, meta) {
  if (cache.has(id)) return cache.get(id)
  if (meta && meta.wrappedKey) {
    try {
      const keyHex = unwrapKey(meta.wrappedKey)
      cache.set(id, keyHex)
      return keyHex
    } catch {
      return null
    }
  }
  return null
}

function closeSession(id) {
  cache.delete(id)
}

export { unwrapKey, openSession, getSession, closeSession }
