/**
 * 主线程:调度与 UI。
 *
 * 职责边界:所有加解密/SM3 在 worker.js 中执行,主线程只做 ——
 *  1. 密钥协商(SM2 封装会话密钥,轻量,主线程直接做)
 *  2. 分块调度(并发/重试/暂停/恢复/对账)
 *  3. HTTP 传输与进度反馈
 *  4. 密钥本地存储(localStorage)
 *
 * 依赖:Vue 与共享国密封装均以 ESM 导入(vite 打包)。
 */
import { createApp } from 'vue'
import * as SM from './shared/crypto.js'

const CHUNK = SM.CHUNK_SIZE
const KEYSTORE = 'sm-vault-keys'
const RETRY_BACKOFF = [1000, 3000, 8000]
const MAX_CELLS = 400 // 分块矩阵最多显示的格数

/* ---------------- 工具 ---------------- */

async function api(path, opts = {}) {
  const res = await fetch(path, opts)
  const ct = res.headers.get('content-type') || ''
  const body = ct.includes('application/json') ? await res.json() : null
  if (!res.ok) {
    const detail = body && body.error ? `: ${body.error}` : ''
    throw new Error(`HTTP ${res.status}${detail}`)
  }
  return body
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(new DOMException('aborted', 'AbortError'))
    const t = setTimeout(resolve, ms)
    if (signal) signal.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('aborted', 'AbortError')) }, { once: true })
  })
}

function fetchWithTimeout(url, opts, signal, ms = 60000) {
  const timeoutSignal = typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(ms) : null
  const combined = signal && timeoutSignal && AbortSignal.any
    ? AbortSignal.any([signal, timeoutSignal])
    : signal || timeoutSignal
  return fetch(url, Object.assign({}, opts, { signal: combined }))
}

function formatBytes(n) {
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

function formatSpeed(bytesPerSec) {
  return formatBytes(bytesPerSec) + '/s'
}

function formatTime(ts) {
  const d = new Date(ts)
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function formatTimeShort(seconds) {
  if (!isFinite(seconds) || seconds < 0) return ''
  const s = Math.round(seconds)
  if (s < 60) return s + 's'
  if (s < 3600) return Math.floor(s / 60) + 'm' + (s % 60) + 's'
  return Math.floor(s / 3600) + 'h' + Math.floor((s % 3600) / 60) + 'm'
}

function shortHex(hex, n = 8) {
  return hex ? hex.slice(0, n) + '…' + hex.slice(-4) : '—'
}

/* ---------------- Worker 客户端(请求-响应关联) ---------------- */

class WorkerClient {
  constructor() {
    this.worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
    this.pending = new Map()
    this.seq = 0
    this.worker.onmessage = (ev) => {
      const m = ev.data
      const p = this.pending.get(m.id)
      if (!p) return
      this.pending.delete(m.id)
      m.t === 'error' ? p.reject(new Error(m.message)) : p.resolve(m)
    }
    this.worker.onerror = (ev) => {
      for (const p of this.pending.values()) p.reject(new Error('Worker 异常: ' + ev.message))
      this.pending.clear()
    }
  }
  /** 发送任务并等待关联响应;transfer 为随消息转移的 ArrayBuffer(零拷贝) */
  call(msg, transfer) {
    const id = 't' + ++this.seq
    msg.id = id
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.worker.postMessage(msg, transfer || [])
    })
  }
  setFile(file) { this.worker.postMessage({ t: 'set-file', file }) }
  encryptChunk(index, keyHex) { return this.call({ t: 'encrypt-chunk', index, keyHex }) }
  decryptChunk(index, keyHex, ivHex, ct, plainLen) {
    return this.call({ t: 'decrypt-chunk', index, keyHex, ivHex, ct, plainLen }, [ct.buffer])
  }
  merkleRoot(chunkHashes) { return this.call({ t: 'merkle-root', chunkHashes }) }
}

/* ---------------- 通用分块调度器 ---------------- */

class NonRetryable extends Error {}

class ChunkScheduler {
  /**
   * @param {object} opts { concurrency, retries, onStatus(i, state), onProgress(done) }
   * job(i, signal):幂等任务。网络类错误抛出以重试;确定性 4xx 抛 NonRetryable 快速失败。
   * run() resolve 时返回 { failed: [indexes], cancelled: bool }。
   */
  constructor(opts) {
    this.concurrency = opts.concurrency
    this.retries = opts.retries
    this.onStatus = opts.onStatus || (() => {})
    this.onProgress = opts.onProgress || (() => {})
    this.paused = false
  }
  run(indexes, job) {
    this.indexes = [...indexes]
    this.job = job
    this.done = 0
    this.failed = []
    this.paused = false
    this.cancelled = false
    this.abort = new AbortController()
    this.inFlight = new Set()
    this.settled = new Promise((resolve) => (this.resolveSettled = resolve))
    this.pump()
    return this.settled
  }
  pump() {
    while (!this.paused && !this.cancelled && this.inFlight.size < this.concurrency && this.indexes.length) {
      const i = this.indexes.shift()
      this.inFlight.add(i)
      this.onStatus(i, 'working')
      this.task(i).finally(() => {
        this.inFlight.delete(i)
        this.maybeSettle()
        this.pump()
      })
    }
  }
  maybeSettle() {
    if (!this.indexes.length && !this.inFlight.size) {
      this.resolveSettled({ failed: this.failed, cancelled: this.cancelled })
    }
  }
  async task(i) {
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (this.cancelled) return
      try {
        await this.job(i, this.abort.signal)
        this.done++
        this.onStatus(i, 'ok')
        this.onProgress(this.done)
        return
      } catch (e) {
        if (this.cancelled) return
        const retryable = !(e instanceof NonRetryable)
        if (attempt === this.retries || !retryable) {
          this.failed.push(i)
          this.onStatus(i, 'failed')
          return
        }
        this.onStatus(i, 'retrying')
        await sleep(RETRY_BACKOFF[attempt] ?? RETRY_BACKOFF.at(-1), this.abort.signal)
        this.onStatus(i, 'working')
      }
    }
  }
  pause() { this.paused = true }
  resume() { this.paused = false; this.pump() }
  cancel() {
    this.cancelled = true
    this.abort.abort()
    this.maybeSettle()
  }
}

/* ---------------- 密钥存储(localStorage) ---------------- */

const keyStore = {
  get(fileId) {
    try { return JSON.parse(localStorage.getItem(KEYSTORE) || '{}')[fileId] || null } catch { return null }
  },
  set(fileId, rec) {
    const all = JSON.parse(localStorage.getItem(KEYSTORE) || '{}')
    all[fileId] = rec
    localStorage.setItem(KEYSTORE, JSON.stringify(all))
  },
  remove(fileId) {
    const all = JSON.parse(localStorage.getItem(KEYSTORE) || '{}')
    delete all[fileId]
    localStorage.setItem(KEYSTORE, JSON.stringify(all))
  },
}

/* ---------------- Vue 应用 ---------------- */

createApp({
  data() {
    return {
      pubkey: '',
      fingerprint: '',
      dragover: false,
      files: [],
      upload: null,       // 进行中的上传任务(响应式)
      downloads: {},      // fileId -> 进行中的下载任务
      sessionKeyFp: '',   // 当前会话 SM4 密钥指纹(协议条展示)
      verified: 0,        // 当前任务已校验块数
      totalChunks: 0,     // 当前任务总块数
      rootHex: '',        // 最近一次 Merkle 根(协议条展示)
      stage: 0,           // 协议条推进到的阶段(0..4)
      worker: null,
      lastSpeedSample: null,
      resumeGate: null,
      notice: null,       // 页面内联通知 { type: 'error'|'info', text }
      noticeTimer: null,
    }
  },
  computed: {
    session() { return this.sessionKeyFp ? shortHex(this.sessionKeyFp) : '—' },
  },
  async mounted() {
    window.__smApp = this // 调试钩子:供 CDP/控制台直接访问组件实例
    this.worker = new WorkerClient()
    await this.refreshFiles()
    try {
      const { publicKey, fingerprint } = await api('/api/pubkey')
      this.pubkey = publicKey
      this.fingerprint = fingerprint
      this.stage = Math.max(this.stage, 1) // SM2 封装就绪
    } catch (e) {
      this.fingerprint = '无法连接服务端'
    }
  },
  methods: {
    notify(text, type = 'error') {
      this.notice = { text, type }
      clearTimeout(this.noticeTimer)
      this.noticeTimer = setTimeout(() => (this.notice = null), 8000)
    },

    /* ---------- 协议条 ---------- */
    stageClass(i) {
      if (i === 3 && this.rootHex && this.stage >= 4) return 'done'
      if (i < this.stage) return 'done'
      if (i === this.stage) return 'active'
      return ''
    },
    stageVal(i) {
      switch (i) {
        case 0: return shortHex(this.fingerprint || '')
        case 1: return this.sessionKeyFp ? shortHex(this.sessionKeyFp) : '待协商'
        case 2: return this.totalChunks ? `${this.verified}/${this.totalChunks}` : '—'
        case 3: return this.rootHex ? shortHex(this.rootHex) : '—'
      }
    },

    /* ---------- 文件选择 ---------- */
    pickFile() { this.$refs.fileInput.click() },
    onPick(e) {
      const f = e.target.files && e.target.files[0]
      e.target.value = ''
      if (f) this.startUpload(f)
    },
    onDrop(e) {
      this.dragover = false
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]
      if (f) this.startUpload(f)
    },

    /* ---------- 上传 ---------- */
    async startUpload(file) {
      if (this.upload && !this.upload.done) {
        this.notify('已有进行中的上传,请先完成或取消')
        return
      }
      const u = {
        id: null, name: file.name, size: file.size,
        chunkCount: 0, phase: 'init', phaseText: '密钥协商…',
        pct: 0, doneBytes: '0 B', totalBytes: formatBytes(file.size),
        speed: '', eta: '', verified: 0,
        chunkCells: [], running: true, done: false,
        paused: false, cancelled: false, error: '',
        _keyHex: '', _bytesDone: 0, _verifiedSet: new Set(), _speedJob: null,
        scheduler: null,
      }
      // 控制函数在 startUpload 即定义:密钥协商阶段也可暂停/取消
      u._pause = () => {
        u.paused = true
        u.running = false
        u.phaseText = '已暂停(在途块继续落盘)'
        if (u.scheduler) u.scheduler.pause()
      }
      u._resume = () => {
        u.paused = false
        u.running = true
        u.phaseText = '续传中…'
        if (u.scheduler) u.scheduler.resume()
        if (this.resumeGate) { this.resumeGate(); this.resumeGate = null }
      }
      u._cancel = () => {
        u.cancelled = true
        if (u.scheduler) u.scheduler.cancel()
        if (this.resumeGate) { this.resumeGate(); this.resumeGate = null }
      }
      this.upload = u
      this.stage = 1
      this.sessionKeyFp = ''
      this.verified = 0
      this.totalChunks = 0
      this.rootHex = ''
      this.lastSpeedSample = { bytes: 0, t: performance.now() }
      u._speedJob = setInterval(() => this.sampleSpeed(u), 500)
      try {
        await this.doUpload(file, u)
      } catch (e) {
        u.phase = 'error'
        u.phaseText = '上传失败: ' + e.message
        u.running = false
      } finally {
        clearInterval(u._speedJob)
      }
    },

    async doUpload(file, u) {
      // 1) SM2 封装随机 SM4 会话密钥(密钥只在本浏览器与本次会话内)
      const keyHex = SM.generateSessionKey()
      u._keyHex = keyHex
      this.sessionKeyFp = SM.sm3Hex(SM.hexToBytes(keyHex))
      const wrapped = SM.sm2WrapKey(this.pubkey, keyHex)

      // 2) 初始化上传会话
      const { id, chunkCount } = await api('/api/upload/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: file.name, size: file.size, chunkSize: CHUNK, wrappedKey: wrapped }),
      })
      u.id = id
      u.chunkCount = chunkCount
      this.totalChunks = chunkCount
      u.chunkCells = Array.from({ length: Math.min(chunkCount, MAX_CELLS) }, (_, i) => ({ i, state: 'pending' }))

      // 空文件:无块可传,直接以 SM3('') 的 Merkle 根完成
      if (chunkCount === 0) {
        const root = (await this.worker.merkleRoot([])).rootHex
        await this.completeUpload(u, root)
        return
      }

      // 3) 分块上传(Worker 加密 + fetch 传输)
      this.worker.setFile(file)
      u.phase = 'uploading'
      u.phaseText = '加密上传中…'
      const chunkHashes = new Array(chunkCount)
      const cipherCache = new Map() // index -> Promise<密文>,重试复用同 IV 同密文(幂等)

      const job = (i, signal) => this.uploadChunkJob(u, id, keyHex, i, signal, chunkHashes, cipherCache)

      let pending = Array.from({ length: chunkCount }, (_, i) => i)
      for (let round = 0; round < 4; round++) {
        await this.waitWhilePaused(u)
        if (u.cancelled) return
        u.scheduler = this.makeUploadScheduler(u)
        const { failed, cancelled } = await u.scheduler.run(pending, job)
        if (cancelled || u.cancelled) return
        // 一轮结束后若仍处于暂停(在途块全部落盘),等用户继续
        await this.waitWhilePaused(u)
        if (u.cancelled) return
        if (!failed.length) break
        if (round === 3) throw new Error('部分块重试后仍失败: ' + failed.slice(0, 10).join(', '))
        // 对账:服务器已落盘的块剔除(请求可能已到端但响应丢失),只补传残留
        const st = await api(`/api/upload/status/${id}`)
        const uploaded = new Set(st.uploaded)
        pending = failed.filter((i) => !uploaded.has(i))
        for (const i of failed) {
          if (uploaded.has(i)) { this.updateCell(u, i, 'skipped'); this.markVerified(u, i) }
        }
      }

      // 4) Merkle 根 + complete(服务端比对一致性,一致才转正)
      u.phase = 'verifying'
      u.phaseText = '文件级完整性校验…'
      const root = (await this.worker.merkleRoot(chunkHashes)).rootHex
      await this.completeUpload(u, root)
    },

    uploadChunkJob(u, id, keyHex, i, signal, chunkHashes, cipherCache) {
      return (async () => {
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
            throw new NonRetryable(`块 ${i} 被服务端拒绝(HTTP ${res.status}${detail ? ': ' + detail : ''})`)
          }
          throw new Error(`块 ${i} 传输失败(HTTP ${res.status})`)
        }
        cipherCache.delete(i)
      })()
    },

    async completeUpload(u, root) {
      const res = await api('/api/upload/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: u.id, rootHash: root }),
      })
      this.rootHex = res.rootHash
      this.stage = 4
      u.phase = 'done'
      u.phaseText = '✓ 上传完成,SM3 + Merkle 完整性校验通过'
      u.pct = 100
      u.done = true
      u.running = false
      u.verified = u.chunkCount
      this.verified = u.chunkCount
      // 密钥与 Merkle 根存入本地,供日后下载解密与完整性交叉核对
      keyStore.set(u.id, { keyHex: u._keyHex, rootHash: res.rootHash, name: u.name })
      await this.refreshFiles()
    },

    makeUploadScheduler(u) {
      return new ChunkScheduler({
        concurrency: 3,
        retries: 3,
        onStatus: (i, state) => {
          if (state === 'ok') this.markVerified(u, i)
          else if (state === 'working') this.updateCell(u, i, 'uploading')
          else if (state === 'retrying') this.updateCell(u, i, 'retrying')
          else if (state === 'failed') this.updateCell(u, i, 'failed')
        },
        onProgress: (done) => this.onUploadProgress(u, done),
      })
    },

    markVerified(u, i) {
      if (!u._verifiedSet.has(i)) {
        u._verifiedSet.add(i)
        u.verified++
        this.verified = u.verified
        this.stage = Math.max(this.stage, 2)
      }
      this.updateCell(u, i, 'verified')
    },

    onUploadProgress(u, done) {
      const bytes = Math.min(done * CHUNK, u.size)
      u._bytesDone = bytes
      u.doneBytes = formatBytes(bytes)
      u.pct = u.size ? Math.round((bytes / u.size) * 100) : 100
    },

    sampleSpeed(u) {
      const now = performance.now()
      const bytes = u._bytesDone || 0
      if (!this.lastSpeedSample) { this.lastSpeedSample = { bytes, t: now }; return }
      const dt = (now - this.lastSpeedSample.t) / 1000
      if (dt < 0.5) return
      const rate = (bytes - this.lastSpeedSample.bytes) / dt
      this.lastSpeedSample = { bytes, t: now }
      if (rate > 0) {
        u.speed = formatSpeed(rate)
        u.eta = formatTimeShort(Math.max(0, u.size - bytes) / rate)
      }
    },

    updateCell(u, i, state) {
      if (i < u.chunkCells.length) u.chunkCells[i].state = state
    },

    waitWhilePaused(u) {
      if (!u.paused) return Promise.resolve()
      return new Promise((resolve) => { this.resumeGate = resolve })
    },

    pauseUpload() { this.upload && this.upload._pause() },
    resumeUpload() { this.upload && this.upload._resume() },
    cancelUpload() {
      const u = this.upload
      if (!u) return
      u._cancel()
      u.phase = 'cancelled'
      u.phaseText = '已取消'
      u.running = false
      u.done = true
      this.sessionKeyFp = ''
      this.verified = 0
      this.totalChunks = 0
      clearInterval(u._speedJob)
    },

    /* ---------- 下载 ---------- */
    hasKey(id) { return !!keyStore.get(id) },
    busy(f) { return !!this.downloads[f.id] },

    async download(f) {
      const rec = keyStore.get(f.id)
      if (!rec) {
        this.notify('此浏览器没有该文件的解密密钥。密钥只保存在上传时的那台浏览器(刷新后仍可解),换设备或清除站点数据后将无法解密。')
        return
      }
      const dl = { pct: 0, phaseText: '准备中…', phase: 'init' }
      this.downloads[f.id] = dl

      // 流式写盘需在用户手势内先打开保存对话框(浏览器限制)
      const fsa = typeof window.showSaveFilePicker === 'function'
      let writable = null
      try {
        if (fsa) {
          const handle = await window.showSaveFilePicker({ suggestedName: f.name })
          writable = await handle.createWritable()
          dl.phaseText = '解密下载(流式写盘,内存 O(1))…'
        } else {
          dl.phaseText = '解密下载(内存组装)…'
        }

        const meta = await api(`/api/files/${f.id}`)
        // 下载前先验 Merkle 根:与服务器 meta 及上传时本地记录三方交叉核对
        const root = (await this.worker.merkleRoot(meta.chunkHashes)).rootHex
        if (root !== meta.rootHash) throw new Error('服务器完整性记录异常(与逐块摘要不一致)')
        if (rec.rootHash && root !== rec.rootHash) throw new Error('文件内容与上传时不一致,可能已被篡改')

        this.sessionKeyFp = SM.sm3Hex(SM.hexToBytes(rec.keyHex))
        this.stage = 1
        this.totalChunks = meta.chunkCount
        this.verified = 0

        const parts = fsa ? null : new Array(meta.chunkCount)
        const scheduler = this.makeDownloadScheduler(dl, meta, fsa)
        const indices = Array.from({ length: meta.chunkCount }, (_, i) => i)
        const { failed } = await scheduler.run(indices, (i, signal) =>
          this.downloadChunkJob(dl, meta, rec.keyHex, i, signal, parts, writable)
        )
        if (failed.length) throw new Error('下载校验失败: ' + failed.join(', '))

        this.rootHex = root
        this.stage = 4
        this.verified = meta.chunkCount
        if (fsa) await writable.close()
        else this.triggerBlobSave(meta, parts)
        dl.phase = 'done'
        dl.phaseText = '✓ 已保存并校验通过'
        dl.pct = 100
      } catch (e) {
        dl.phase = 'error'
        dl.phaseText = '下载失败: ' + e.message
        if (writable) await writable.close().catch(() => {})
      } finally {
        // 保留数秒让用户看到结果,随后恢复按钮
        setTimeout(() => { delete this.downloads[f.id] }, 8000)
      }
    },

    async downloadChunkJob(dl, meta, keyHex, i, signal, parts, writable) {
      const res = await fetchWithTimeout(`/api/download/${meta.id}/chunk/${i}`, { signal })
      if (!res.ok) throw new Error(`块 ${i} 下载失败(HTTP ${res.status})`)
      const buf = new Uint8Array(await res.arrayBuffer())
      const ivHex = SM.bytesToHex(buf.subarray(0, 16))
      const ct = buf.subarray(16)
      const plainLen = Math.min(meta.chunkSize, meta.size - i * meta.chunkSize)
      const { pt: plain, ptHashHex } = await this.worker.decryptChunk(i, keyHex, ivHex, ct, plainLen)
      if (ptHashHex !== meta.chunkHashes[i]) {
        throw new NonRetryable(`块 ${i} SM3 校验失败:内容与服务器记录不一致,可能已被篡改`)
      }
      if (writable) await writable.write(plain)
      else parts[i] = plain
    },

    makeDownloadScheduler(dl, meta, fsa) {
      return new ChunkScheduler({
        concurrency: fsa ? 1 : 4, // 流式写盘必须按序写入
        retries: 3,
        onStatus: (i, state) => {
          if (state === 'failed') dl.phaseText = '下载出错,自动重试…'
        },
        onProgress: (done) => {
          dl.pct = meta.chunkCount ? Math.round((done / meta.chunkCount) * 100) : 100
          dl.phaseText = `解密校验中 ${done}/${meta.chunkCount}`
        },
      })
    },

    triggerBlobSave(meta, parts) {
      const blob = new Blob(parts, { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = meta.name
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 60000)
    },

    /* ---------- 文件管理 ---------- */
    async refreshFiles() {
      try {
        const { files } = await api('/api/files')
        this.files = files
      } catch (e) {
        this.files = []
      }
    },
    async remove(f) {
      if (!confirm(`删除「${f.name}」?删除后不可恢复。`)) return
      await api(`/api/files/${f.id}`, { method: 'DELETE' })
      keyStore.remove(f.id)
      await this.refreshFiles()
    },
    async copyPubkey() {
      try { await navigator.clipboard.writeText(this.pubkey) } catch { /* 剪贴板不可用时忽略 */ }
    },

    /* ---------- 模板辅助 ---------- */
    // 注意:模板编译出的渲染函数不闭包模块作用域,模板中引用的格式化函数必须挂到组件上
    formatBytes,
    formatTime,
    phaseCls(u) {
      if (u.phase === 'done') return 'done'
      if (u.phase === 'error' || u.phase === 'cancelled') return 'error'
      return ''
    },
    cellCls(s) { return s },
    cellName(s) {
      return { pending: '待处理', uploading: '加密/传输中', retrying: '失败重试中', verified: '已校验', failed: '失败', skipped: '已存在,跳过' }[s] || s
    },
  },
}).mount('#app')
