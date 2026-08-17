/**
 * 全链路黑盒测试:模拟浏览器客户端(共享同一份 shared/crypto.js),走
 * 加密上传 → 转正 → 下载 → 解密校验 → 字节比对 的完整流程。
 *
 * 覆盖:基础往返、边界尺寸、空文件、篡改检测、断点续传、负面用例。
 * 服务端进程内启动(listen(0)),数据目录隔离到临时目录。
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

// SM_DATA_DIR 必须早于任何 store 模块求值设置(ESM import 会提升,故用动态 import
// 保证顺序:store.js 顶层按此 env 计算数据目录)。
process.env.SM_DATA_DIR = mkdtempSync(join(tmpdir(), 'sm-e2e-'))

const C = await import('../web/secure/crypto.js')
const store = await import('../src/store.js')
const { createApp } = await import('../server.js')

const CHUNK = C.CHUNK_SIZE

let base
let server

before(() => {
  server = createApp().listen(0)
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => server.close())

async function api(path, opts = {}) {
  const res = await fetch(base + path, opts)
  let body = null
  const ct = res.headers.get('content-type') ?? ''
  if (ct.includes('application/json')) body = await res.json()
  else body = new Uint8Array(await res.arrayBuffer())
  return { status: res.status, body }
}

async function getPubkey() {
  const { body } = await api('/api/pubkey')
  return body.publicKey
}

/**
 * 并发受限的块上传调度器(与浏览器端同一语义:同密文重试、对账跳过)。
 * limit: 最多上传的块数(默认不限),用于模拟部分上传后中断。
 */
async function uploadChunks({ id, keyHex, chunkCount, data, skip = new Set(), concurrency = 3, limit = Infinity }) {
  const chunkHashes = new Array(chunkCount)
  let next = 0
  let done = 0

  async function worker() {
    while (true) {
      if (done >= limit) return
      const i = next++
      if (i >= chunkCount) return
      if (skip.has(i)) continue
      done++ // 拿到索引即占名额,保证 limit 精确
      const off = i * CHUNK
      const len = Math.min(CHUNK, data.length - off)
      const plain = data.subarray(off, off + len)
      const { ivHex, ct, ptHashHex } = C.chunkEncrypt(keyHex, plain)
      chunkHashes[i] = ptHashHex
      const body = new Uint8Array(16 + ct.length)
      body.set(C.hexToBytes(ivHex), 0)
      body.set(ct, 16)
      const { status } = await api(`/api/upload/chunk/${id}/${i}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Hash': ptHashHex },
        body,
      })
      if (status !== 204) throw new Error(`块 ${i} 上传失败: HTTP ${status}`)
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker))
  return chunkHashes
}

async function uploadFile(data, name = 'test.bin') {
  const publicKey = await getPubkey()
  const keyHex = C.generateSessionKey()
  const wrappedKey = C.sm2WrapKey(publicKey, keyHex)
  const { status, body } = await api('/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, size: data.length, chunkSize: CHUNK, wrappedKey }),
  })
  assert.equal(status, 201, `init 应 201,实得 ${status}`)
  const { id, chunkCount } = body
  const chunkHashes = await uploadChunks({ id, keyHex, chunkCount, data })
  const rootHash = C.merkleRoot(chunkHashes)
  const completeRes = await api('/api/upload/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, rootHash }),
  })
  assert.equal(completeRes.status, 200, `complete 应 200,实得 ${completeRes.status}`)
  return { id, keyHex, rootHash, chunkHashes }
}

/** 下载并解密校验,逐块 SM3 比对 + Merkle 根比对;失败抛错 */
async function downloadAndVerify(id, keyHex, expected) {
  const { status, body: meta } = await api(`/api/files/${id}`)
  assert.equal(status, 200)
  const parts = []
  for (let i = 0; i < meta.chunkCount; i++) {
    const { status: s, body: buf } = await api(`/api/download/${id}/chunk/${i}`)
    assert.equal(s, 200)
    const ivHex = C.bytesToHex(buf.subarray(0, 16))
    const ct = buf.subarray(16)
    const plainLen = Math.min(meta.chunkSize, meta.size - i * meta.chunkSize)
    const { plain, ptHashHex } = C.chunkDecrypt(keyHex, ivHex, ct, plainLen)
    assert.equal(ptHashHex, meta.chunkHashes[i], `块 ${i} SM3 与服务器记录不一致(数据被篡改)`)
    parts.push(plain)
  }
  assert.equal(C.merkleRoot(meta.chunkHashes), meta.rootHash, 'Merkle 根与服务器 meta 不一致')
  const merged = new Uint8Array(meta.size)
  let off = 0
  for (const p of parts) {
    merged.set(p, off)
    off += p.length
  }
  assert.deepEqual(merged, expected, '解密内容与原始文件字节不一致')
  return merged
}

test('基础往返:随机 5MiB+3B 文件(2 块)', async () => {
  const data = new Uint8Array(randomBytes(CHUNK + 3))
  const { id, keyHex } = await uploadFile(data)
  await downloadAndVerify(id, keyHex, data)
})

test('边界尺寸:0B / 17B / 恰 4MiB / 4MiB+1 / 8MiB+3(3 块)', async () => {
  for (const size of [0, 17, CHUNK, CHUNK + 1, CHUNK * 2 + 3]) {
    const data = new Uint8Array(randomBytes(size))
    const { id, keyHex } = await uploadFile(data)
    await downloadAndVerify(id, keyHex, data)
  }
})

test('篡改检测:complete 后改磁盘某块 1 字节,下载校验必须失败', async () => {
  const data = new Uint8Array(randomBytes(CHUNK * 2 + 3))
  const { id, keyHex } = await uploadFile(data)
  // 直接改落盘密文块(IV 之后的第一个字节)
  const buf = store.readChunkFile('files', id, 1)
  buf[16] ^= 0xff
  store.writeChunkFile('files', id, 1, buf)
  await assert.rejects(downloadAndVerify(id, keyHex, data), /SM3 与服务器记录不一致/)
})

test('断点续传:只传部分块后对账跳过,complete 成功', async () => {
  const data = new Uint8Array(randomBytes(CHUNK * 3 + 7)) // 4 块
  const publicKey = await getPubkey()
  const keyHex = C.generateSessionKey()
  const wrappedKey = C.sm2WrapKey(publicKey, keyHex)
  const { status, body } = await api('/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'resume.bin', size: data.length, chunkSize: CHUNK, wrappedKey }),
  })
  assert.equal(status, 201)
  const { id, chunkCount } = body

  // 只传块 0、1,模拟中断
  const hashes = await uploadChunks({ id, keyHex, chunkCount, data, concurrency: 1, limit: 2 })
  assert.ok(hashes[0] && hashes[1])
  assert.equal(hashes[2], undefined)

  // 对账:status 只含已落盘块
  const st = await api(`/api/upload/status/${id}`)
  assert.deepEqual(st.body.uploaded, [0, 1])

  // 恢复:跳过 [0,1],补传 2、3
  const resumed = await uploadChunks({ id, keyHex, chunkCount, data, skip: new Set(st.body.uploaded) })
  for (let i = 0; i < chunkCount; i++) if (resumed[i]) hashes[i] = resumed[i] // 合并两轮摘要
  const rootHash = C.merkleRoot(hashes)
  const done = await api('/api/upload/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, rootHash }),
  })
  assert.equal(done.status, 200)
  await downloadAndVerify(id, keyHex, data)
})

test('负面:错误 X-Chunk-Hash 上传块 → 422', async () => {
  const data = new Uint8Array(randomBytes(1024))
  const publicKey = await getPubkey()
  const keyHex = C.generateSessionKey()
  const { status, body } = await api('/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'bad.bin',
      size: 1024,
      chunkSize: CHUNK,
      wrappedKey: C.sm2WrapKey(publicKey, keyHex),
    }),
  })
  const { id } = body
  const { ivHex, ct } = C.chunkEncrypt(keyHex, data)
  const buf = new Uint8Array(16 + ct.length)
  buf.set(C.hexToBytes(ivHex), 0)
  buf.set(ct, 16)
  const bad = await api(`/api/upload/chunk/${id}/0`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Hash': 'f'.repeat(64) },
    body: buf,
  })
  assert.equal(bad.status, 422)
})

test('负面:缺块 complete → 400;未知会话 status → 404;未转正文件下载 → 404', async () => {
  const data = new Uint8Array(randomBytes(CHUNK + 1))
  const publicKey = await getPubkey()
  const keyHex = C.generateSessionKey()
  const { status, body } = await api('/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'incomplete.bin',
      size: data.length,
      chunkSize: CHUNK,
      wrappedKey: C.sm2WrapKey(publicKey, keyHex),
    }),
  })
  const { id } = body
  // 一个块都没传就 complete
  const emptyRoot = C.merkleRoot([])
  const done = await api('/api/upload/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, rootHash: emptyRoot }),
  })
  assert.equal(done.status, 400, '缺块 complete 应 400')

  const st = await api('/api/upload/status/not-a-uuid')
  assert.equal(st.status, 404)

  const dl = await api(`/api/download/${id}/chunk/0`)
  assert.equal(dl.status, 404, '未转正文件不可下载')
})

test('文件列表与删除', async () => {
  const data = new Uint8Array(randomBytes(100))
  const { id } = await uploadFile(data, 'list-test.txt')
  const { status, body } = await api('/api/files')
  assert.equal(status, 200)
  const found = body.files.find((f) => f.id === id)
  assert.ok(found, '列表应包含刚上传的文件')
  assert.equal(found.name, 'list-test.txt')
  const del = await api(`/api/files/${id}`, { method: 'DELETE' })
  assert.equal(del.status, 204)
  const after = await api(`/api/files/${id}`)
  assert.equal(after.status, 404, '删除后详情应 404')
  assert.equal(existsSync(join(store.DATA_DIR, 'files', id)), false)
})
