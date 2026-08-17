/**
 * 算法层测试:已知答案向量(KAT)+ sm-crypto(纯 JS)与 Node 原生 crypto 互操作。
 * 互操作测试是本项目的关键保险:服务端用原生 sm4-cbc/sm3 做校验快路径,
 * 浏览器用 sm-crypto,两端必须字节级一致。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { sm2 } from 'sm-crypto'

import * as C from '../web/secure/crypto.js'

const SM3_ABC = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'

function nativeSm3Hex(buf) {
  return createHash('sm3').update(buf).digest('hex')
}

function nativeSm4Encrypt(keyHex, ivHex, plain) {
  const cipher = createCipheriv('sm4-cbc', Buffer.from(keyHex, 'hex'), Buffer.from(ivHex, 'hex'))
  return Buffer.concat([cipher.update(plain), cipher.final()])
}

function nativeSm4Decrypt(keyHex, ivHex, ct) {
  const decipher = createDecipheriv('sm4-cbc', Buffer.from(keyHex, 'hex'), Buffer.from(ivHex, 'hex'))
  return Buffer.concat([decipher.update(ct), decipher.final()])
}

test('SM3 已知答案向量: sm3("abc")', () => {
  assert.equal(C.sm3Hex(new TextEncoder().encode('abc')), SM3_ABC)
})

test('SM3 互操作: 纯 JS 与 Node 原生对随机数据一致', () => {
  for (const len of [0, 1, 15, 16, 17, 1000, 1_000_000]) {
    const data = randomBytes(len)
    assert.equal(C.sm3Hex(new Uint8Array(data)), nativeSm3Hex(data), `len=${len}`)
  }
})

test('SM4 往返: 纯 JS 加密 → 纯 JS 解密,多组长度', () => {
  const keyHex = C.bytesToHex(new Uint8Array(randomBytes(16)))
  for (const len of [0, 1, 15, 16, 17, 255, 256, 100_000, 4 * 1024 * 1024 + 3]) {
    const plain = new Uint8Array(randomBytes(len))
    const { ivHex, ct } = C.chunkEncrypt(keyHex, plain)
    const { plain: back, ptHashHex } = C.chunkDecrypt(keyHex, ivHex, ct, len)
    assert.deepEqual(back, plain, `len=${len}`)
    assert.equal(ptHashHex, C.sm3Hex(plain), `len=${len} 摘要一致`)
  }
})

test('SM4 互操作: 纯 JS 加密 ↔ Node 原生解密(服务端校验路径)', () => {
  const keyHex = C.bytesToHex(new Uint8Array(randomBytes(16)))
  const plain = new Uint8Array(randomBytes(2 * 1024 * 1024 + 11)) // 非 16 倍数
  const { ivHex, ct, ptHashHex } = C.chunkEncrypt(keyHex, plain)
  const back = nativeSm4Decrypt(keyHex, ivHex, Buffer.from(ct))
  assert.deepEqual(new Uint8Array(back), plain, '字节级一致')
  assert.equal(nativeSm3Hex(back), ptHashHex, '服务端原生 SM3 校验通过')
})

test('SM4 互操作: Node 原生加密 ↔ 纯 JS 解密(反向路径)', () => {
  const keyHex = C.bytesToHex(new Uint8Array(randomBytes(16)))
  const ivHex = C.bytesToHex(C.randBytes(16))
  const plain = randomBytes(3 * 1024 * 1024 - 7)
  const ct = nativeSm4Encrypt(keyHex, ivHex, plain)
  const { plain: back } = C.chunkDecrypt(keyHex, ivHex, new Uint8Array(ct), plain.length)
  assert.deepEqual(new Uint8Array(back), new Uint8Array(plain), '字节级一致')
})

test('SM2 封装/解封: 16 字节会话密钥往返', () => {
  const { publicKey, privateKey } = sm2.generateKeyPairHex()
  const keyHex = C.generateSessionKey()
  const wrapped = C.sm2WrapKey(publicKey, keyHex)
  assert.equal(C.sm2UnwrapKey(privateKey, wrapped), keyHex)
})

test('Merkle 根: 确定性 + 顺序敏感', () => {
  const a = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]
  assert.equal(C.merkleRoot(a), C.merkleRoot(a))
  assert.notEqual(C.merkleRoot(a), C.merkleRoot([...a].reverse()))
  // 空块列表 = SM3('') 的互操作一致性
  assert.equal(C.merkleRoot([]), nativeSm3Hex(Buffer.alloc(0)))
})

test('密文长度公式(PKCS#7:16 倍数也要补一整块)', () => {
  assert.equal(C.cipherLenOf(0), 16 + 16) // 空明文也补满一块 0x10
  assert.equal(C.cipherLenOf(3), 16 + 16)
  assert.equal(C.cipherLenOf(16), 16 + 32) // 整倍数 + 一整块填充
  assert.equal(C.cipherLenOf(17), 16 + 32)
  assert.equal(C.cipherLenOf(32), 16 + 48)
  assert.equal(C.cipherLenOf(4 * 1024 * 1024), 16 + (4 * 1024 * 1024 + 16))
  // 与 sm-crypto 实际输出逐项对拍
  const keyHex = C.bytesToHex(new Uint8Array(16))
  for (const len of [0, 1, 15, 16, 17, 31, 32, 33, 1000, 4 * 1024 * 1024]) {
    const { ivHex, ct } = C.chunkEncrypt(keyHex, new Uint8Array(len))
    assert.equal(16 + ct.length, C.cipherLenOf(len), `len=${len} 与 sm-crypto 实际输出一致`)
  }
})
