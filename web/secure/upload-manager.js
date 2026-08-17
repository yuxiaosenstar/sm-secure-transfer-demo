/**
 * 上传编排(传输逻辑):密钥协商 → 分块加密上传 → 四轮调度+对账 → Merkle 校验。
 *
 * 与 UI 的边界:
 *  - 组件创建任务对象并先赋值到 `this.upload`(Vue 3 惰性 deep-reactive,首次
 *    读取返回代理),再把读到的代理经 start() 传给本类 —— manager 只写代理的
 *    展示字段(chunkCells/doneBytes/speed/eta/...),即触发模板更新。
 *  - 组件自有状态(协议条:sessionKeyFp/verified/totalChunks/rootHex/stage、
 *    文件列表)经回调同步回组件:onSession(patch|fn)、onFilesChanged()、getPubkey()。
 *  - 私有字段(_keyHex/_bytesDone/_verifiedSet/scheduler/... )全部留本类实例,
 *    不上任务对象,避免污染响应式代理。
 *  - manager 实例由组件 markRaw() 包装后挂 data,防内部 AbortController/Set/Map
 *    被代理包裹。
 *
 * 已知行为差异(相对拆分前):旧代码把 raw 任务对象传给调度回调,UI 靠
 * `this.verified` 等响应式写入"捎带"刷新(上传每块一次);改传代理后渲染节拍
 * 几乎不变,是唯一差异,已接受。
 */
import { fetchWithTimeout, api } from './http.js'
import { formatBytes, formatSpeed, formatTimeShort } from './format.js'
import { ChunkScheduler, NonRetryable } from './scheduler.js'
import { WorkerClient } from './worker-client.js'
import { keyStore } from './keystore.js'
import * as SM from './crypto.js'

const CHUNK = SM.CHUNK_SIZE
const MAX_CELLS = 400 // 分块矩阵最多显示的格数

export class UploadManager {
  /**
   * @param {WorkerClient} worker 与 UI 共享的 worker 客户端(mounted 同步创建)
   * @param {object} cb { onSession(patch|fn), onFilesChanged(), getPubkey() }
   */
  constructor(worker, cb) {
    this.worker = worker
    this.cb = cb
    this.display = null // 组件任务对象的响应式代理(展示字段写这里)
    this.resumeGate = null // 暂停等待:非空时调度在 waitWhilePaused 处挂着
    this.lastSpeedSample = null
    this.speedJob = null
    this.scheduler = null
  }

  /** 上传入口:组件创建 u 并先赋值(this.upload = u)后再调用,display 即代理 */
  async start(file, display) {
    this.display = display
    this._verifiedSet = new Set()
    this.lastSpeedSample = { bytes: 0, t: performance.now() }
    this.speedJob = setInterval(() => this.sampleSpeed(), 500)
    try {
      await this.doUpload(file)
    } catch (e) {
      // 错误收口:密钥协商/init/四轮耗尽/complete 的异常统一落到任务状态
      this.display.phase = 'error'
      this.display.phaseText = '上传失败: ' + e.message
      this.display.running = false
    } finally {
      clearInterval(this.speedJob)
      this.speedJob = null
    }
  }

  async doUpload(file) {
    const d = this.display
    // 1) SM2 封装随机 SM4 会话密钥(密钥只在本浏览器与本次会话内)
    const keyHex = SM.generateSessionKey()
    this._keyHex = keyHex
    this.cb.onSession({ sessionKeyFp: SM.sm3Hex(SM.hexToBytes(keyHex)) })
    const wrapped = SM.sm2WrapKey(this.cb.getPubkey(), keyHex)

    // 2) 初始化上传会话
    const { id, chunkCount } = await api('/api/upload/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: file.name, size: file.size, chunkSize: CHUNK, wrappedKey: wrapped }),
    })
    d.id = id
    d.chunkCount = chunkCount
    this.cb.onSession({ totalChunks: chunkCount })
    d.chunkCells = Array.from({ length: Math.min(chunkCount, MAX_CELLS) }, (_, i) => ({ i, state: 'pending' }))

    // 空文件:无块可传,直接以 SM3('') 的 Merkle 根完成
    if (chunkCount === 0) {
      const root = (await this.worker.merkleRoot([])).rootHex
      await this.completeUpload(root)
      return
    }

    // 3) 分块上传(Worker 加密 + fetch 传输)
    this.worker.setFile(file)
    d.phase = 'uploading'
    d.phaseText = '加密上传中…'
    const chunkHashes = new Array(chunkCount)
    const cipherCache = new Map() // index -> Promise<密文>,重试复用同 IV 同密文(幂等)

    const job = (i, signal) => this.uploadChunkJob(id, keyHex, i, signal, chunkHashes, cipherCache)

    // 四轮调度:每轮内每块已重试 3 次,一轮结束后对账剔除服务器已落盘的块
    // (块上传成功但响应丢失的场景 —— 服务器收到并校验通过才会落盘,所以"已
    // 落盘"即"已成功"),只对残留块开下一轮。这是网络丢包下的最终一致性兜底。
    let pending = Array.from({ length: chunkCount }, (_, i) => i)
    for (let round = 0; round < 4; round++) {
      await this.waitWhilePaused()
      if (d.cancelled) return
      this.scheduler = this.makeUploadScheduler()
      const { failed, cancelled } = await this.scheduler.run(pending, job)
      if (cancelled || d.cancelled) return
      // 一轮结束后若仍处于暂停(在途块全部落盘),等用户继续
      await this.waitWhilePaused()
      if (d.cancelled) return
      if (!failed.length) break
      if (round === 3) throw new Error('部分块重试后仍失败: ' + failed.slice(0, 10).join(', '))
      // 对账:服务器已落盘的块剔除(请求可能已到端但响应丢失),只补传残留
      const st = await api(`/api/upload/status/${id}`)
      const uploaded = new Set(st.uploaded)
      pending = failed.filter((i) => !uploaded.has(i))
      for (const i of failed) {
        if (uploaded.has(i)) { this.updateCell(i, 'skipped'); this.markVerified(i) }
      }
    }

    // 4) Merkle 根 + complete(服务端比对一致性,一致才转正)
    d.phase = 'verifying'
    d.phaseText = '文件级完整性校验…'
    const root = (await this.worker.merkleRoot(chunkHashes)).rootHex
    await this.completeUpload(root)
  }

  async uploadChunkJob(id, keyHex, i, signal, chunkHashes, cipherCache) {
    // cipherCache 缓存块密文:重试时复用同一 IV+密文+哈希,保证对服务端幂等
    // (服务端按"哈希+长度"校验后覆盖落盘,同内容重复写入结果一致)。
    // 成功后即删除缓存释放内存;失败保留,供下一轮重试继续复用。
    if (!cipherCache.has(i)) cipherCache.set(i, this.worker.encryptChunk(i, keyHex))
    const { ivHex, ct, ptHashHex } = await cipherCache.get(i)
    chunkHashes[i] = ptHashHex
    const body = new Uint8Array(16 + ct.length)
    body.set(SM.hexToBytes(ivHex), 0)
    body.set(ct, 16)
    const res = await fetchWithTimeout(`/api/upload/chunk/${id}/${i}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Hash': ptHashHex },
      body,
      signal,
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      if (res.status >= 400 && res.status < 500) {
        // 4xx = 服务端确定性拒绝(校验失败/越界),重试结果必然相同 → 不重试
        throw new NonRetryable(`块 ${i} 被服务端拒绝(HTTP ${res.status}${detail ? ': ' + detail : ''})`)
      }
      throw new Error(`块 ${i} 传输失败(HTTP ${res.status})`)
    }
    cipherCache.delete(i)
  }

  async completeUpload(root) {
    const d = this.display
    const res = await api('/api/upload/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: d.id, rootHash: root }),
    })
    this.cb.onSession({ rootHex: res.rootHash, stage: 4 })
    d.phase = 'done'
    d.phaseText = '✓ 上传完成,SM3 + Merkle 完整性校验通过'
    d.pct = 100
    d.done = true
    d.running = false
    d.verified = d.chunkCount
    this.cb.onSession({ verified: d.chunkCount })
    // 密钥与 Merkle 根存入本地,供日后下载解密与完整性交叉核对
    keyStore.set(d.id, { keyHex: this._keyHex, rootHash: res.rootHash, name: d.name })
    await this.cb.onFilesChanged()
  }

  makeUploadScheduler() {
    return new ChunkScheduler({
      concurrency: 3,
      retries: 3,
      onStatus: (i, state) => {
        if (state === 'ok') this.markVerified(i)
        else if (state === 'working') this.updateCell(i, 'uploading')
        else if (state === 'retrying') this.updateCell(i, 'retrying')
        else if (state === 'failed') this.updateCell(i, 'failed')
      },
      onProgress: (done) => this.onUploadProgress(done),
    })
  }

  markVerified(i) {
    if (!this._verifiedSet.has(i)) {
      this._verifiedSet.add(i)
      this.display.verified++
      // 组件侧协议条同步:verified 取任务对象值,stage 至少推进到 2(校验阶段)
      this.cb.onSession((s) => ({ verified: this.display.verified, stage: Math.max(s.stage, 2) }))
    }
    this.updateCell(i, 'verified')
  }

  onUploadProgress(done) {
    const d = this.display
    const bytes = Math.min(done * CHUNK, d.size)
    this._bytesDone = bytes
    d.doneBytes = formatBytes(bytes)
    d.pct = d.size ? Math.round((bytes / d.size) * 100) : 100
  }

  sampleSpeed() {
    const d = this.display
    const now = performance.now()
    const bytes = this._bytesDone || 0
    if (!this.lastSpeedSample) { this.lastSpeedSample = { bytes, t: now }; return }
    const dt = (now - this.lastSpeedSample.t) / 1000
    if (dt < 0.5) return
    const rate = (bytes - this.lastSpeedSample.bytes) / dt
    this.lastSpeedSample = { bytes, t: now }
    if (rate > 0) {
      d.speed = formatSpeed(rate)
      d.eta = formatTimeShort(Math.max(0, d.size - bytes) / rate)
    }
  }

  updateCell(i, state) {
    if (i < this.display.chunkCells.length) this.display.chunkCells[i].state = state
  }

  waitWhilePaused() {
    if (!this.display.paused) return Promise.resolve()
    return new Promise((resolve) => { this.resumeGate = resolve })
  }

  /* ---------- 供组件委托的公开控制 ---------- */
  // 控制函数在 start 即可用:密钥协商阶段也可暂停/取消
  pause() {
    const d = this.display
    if (!d) return
    d.paused = true
    d.running = false
    d.phaseText = '已暂停(在途块继续落盘)'
    if (this.scheduler) this.scheduler.pause()
  }
  resume() {
    const d = this.display
    if (!d) return
    d.paused = false
    d.running = true
    d.phaseText = '续传中…'
    if (this.scheduler) this.scheduler.resume()
    if (this.resumeGate) { this.resumeGate(); this.resumeGate = null }
  }
  cancel() {
    const d = this.display
    if (!d) return
    d.cancelled = true
    if (this.scheduler) this.scheduler.cancel()
    if (this.resumeGate) { this.resumeGate(); this.resumeGate = null }
  }
}
