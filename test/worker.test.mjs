/**
 * Worker 核心协议测试:直接驱动 worker-core 的 createWorkerHandlers(纯逻辑),
 * 覆盖 set-file → encrypt-chunk → decrypt-chunk → merkle-root 完整消息协议,
 * 以及启动 KAT 自检。worker.js 只是把本模块的处理器接到 self.postMessage,
 * 因此这里等价于浏览器端 worker 的实际装配与行为,且无需构建产物。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import * as C from '../web/secure/crypto.js'
import { selfCheck, createWorkerHandlers } from '../web/secure/worker-core.js'

/** 以数组收集 post 消息,模拟 worker 的 self.postMessage 宿主 */
function makeHarness() {
  const messages = []
  const onMessage = createWorkerHandlers({ post: (obj) => messages.push(obj) })
  return { messages, onMessage }
}

function waitFor(cond, timeout = 5000) {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    ;(function poll() {
      if (cond()) return resolve()
      if (Date.now() - start > timeout) return reject(new Error('等待 Worker 消息超时'))
      setTimeout(poll, 20)
    })()
  })
}

test('启动自检:SM3 公开测试向量', () => {
  assert.doesNotThrow(() => selfCheck())
})

test('Worker 协议全链路(KAT 自检 → 加密 → 解密 → Merkle)', async () => {
  const { messages, onMessage } = makeHarness()

  const data = randomBytes(2 * 1024 * 1024 + 3)
  const blob = new Blob([data]) // Node 的 Blob,slice/arrayBuffer 语义与浏览器一致
  const keyHex = C.generateSessionKey()
  const send = (msg) => onMessage(msg)

  // 1) set-file + encrypt-chunk(index 0,数据不足 4MiB 只有一块)
  send({ t: 'set-file', file: blob })
  send({ t: 'encrypt-chunk', id: 'e1', index: 0, keyHex })
  await waitFor(() => messages.some((m) => m.t === 'chunk-encrypted'))
  const enc = messages.find((m) => m.t === 'chunk-encrypted')
  assert.equal(enc.id, 'e1')
  assert.equal(enc.ptHashHex, C.sm3Hex(new Uint8Array(data)), '明文 SM3 应等于直接计算的摘要')
  const expectLen = C.cipherLenOf(data.length)
  assert.equal(enc.ct.length, expectLen - 16, '密文长度符合 PKCS#7')

  // 2) decrypt-chunk:还原明文
  send({ t: 'decrypt-chunk', id: 'd1', index: 0, keyHex, ivHex: enc.ivHex, ct: enc.ct, plainLen: data.length })
  await waitFor(() => messages.some((m) => m.t === 'chunk-decrypted'))
  const dec = messages.find((m) => m.t === 'chunk-decrypted')
  assert.deepEqual(new Uint8Array(dec.pt), new Uint8Array(data), '解密明文与原始字节一致')
  assert.equal(dec.ptHashHex, enc.ptHashHex)

  // 3) merkle-root
  send({ t: 'merkle-root', id: 'm1', chunkHashes: [enc.ptHashHex] })
  await waitFor(() => messages.some((m) => m.t === 'merkle-root-done'))
  const root = messages.find((m) => m.t === 'merkle-root-done')
  assert.equal(root.rootHex, C.merkleRoot([enc.ptHashHex]))
})

test('错误路径:未知任务类型与未设置文件', () => {
  const { messages, onMessage } = makeHarness()
  onMessage({ t: 'encrypt-chunk', id: 'x', index: 0, keyHex: '00'.repeat(16) })
  assert.equal(messages.at(-1).t, 'error', '未设置文件应报 error')
  onMessage({ t: 'nope', id: 'y' })
  assert.equal(messages.at(-1).t, 'error')
  assert.match(messages.at(-1).message, /未知任务类型/)
})
