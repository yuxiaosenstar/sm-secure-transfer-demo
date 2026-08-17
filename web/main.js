/**
 * 主线程:Vue 组件(页面逻辑)。
 *
 * 职责边界(拆分后):main.js 只保留 UI 状态与事件委托;上传/下载的传输编排
 * (密钥协商、分块调度、重试对账、Merkle 校验、写盘)全部在独立的 manager
 * 模块中,经回调与本组件通信:
 *  - upload-manager.js / download-manager.js:传输编排
 *  - worker-client.js / worker.js / worker-core.js:Worker 加解密
 *  - http.js / scheduler.js / keystore.js:HTTP、调度器、密钥存储
 *
 * 通信方式:组件创建任务对象先赋值到响应式 data,再把读到的代理传给 manager;
 * manager 只写代理的展示字段即触发模板更新。组件自有状态经回调注入:
 *  - onSession(patch|fn)  协议条同步(函数式支持 stage max 语义)
 *  - onFilesChanged()     文件列表刷新(completeUpload 后保持顺序)
 *  - onDownloadEnd(id)    下载行保留数秒后清理
 *  - getPubkey()          上传 SM2 封装用的服务端公钥
 *
 * 兼容红线:模板所有绑定(见 index.html)与 smoke 脚本的
 * window.__smApp.upload / pauseUpload() / resumeUpload() 原样保留。
 */
import { createApp, markRaw } from 'vue'
import { api } from './http.js'
import { formatBytes, formatTime, shortHex } from './format.js'
import { WorkerClient } from './worker-client.js'
import { UploadManager } from './upload-manager.js'
import { DownloadManager } from './download-manager.js'
import { keyStore } from './keystore.js'

createApp({
  data() {
    return {
      pubkey: '',
      fingerprint: '',
      dragover: false,
      files: [],
      upload: null,       // 进行中的上传任务(响应式代理,manager 写展示字段)
      downloads: {},      // fileId -> 进行中的下载任务
      sessionKeyFp: '',   // 当前会话 SM4 密钥指纹(协议条展示)
      verified: 0,        // 当前任务已校验块数
      totalChunks: 0,     // 当前任务总块数
      rootHex: '',        // 最近一次 Merkle 根(协议条展示)
      stage: 0,           // 协议条推进到的阶段(0..4)
      notice: null,       // 页面内联通知 { type: 'error'|'info', text }
      noticeTimer: null,
      // markRaw 包住 manager:防内部 AbortController/Set/Map/scheduler 被代理包裹
      uploadMgr: null,
      downloadMgr: null,
    }
  },
  computed: {
    session() { return this.sessionKeyFp ? shortHex(this.sessionKeyFp) : '—' },
  },
  async mounted() {
    window.__smApp = this // 调试钩子:供 CDP/控制台直接访问组件实例
    // manager 必须在第一个 await 前同步建好,否则 mounted 期间 drop 会产生未处理 rejection
    const worker = new WorkerClient()
    this.uploadMgr = markRaw(new UploadManager(worker, {
      onSession: (p) => Object.assign(this, typeof p === 'function' ? p(this) : p),
      onFilesChanged: () => this.refreshFiles(),
      getPubkey: () => this.pubkey,
    }))
    this.downloadMgr = markRaw(new DownloadManager(worker, {
      onSession: (p) => Object.assign(this, typeof p === 'function' ? p(this) : p),
      // 保留数秒让用户看到结果,随后恢复按钮
      onDownloadEnd: (fileId) => setTimeout(() => { delete this.downloads[fileId] }, 8000),
    }))
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
      }
      this.upload = u
      this.stage = 1
      this.sessionKeyFp = ''
      this.verified = 0
      this.totalChunks = 0
      this.rootHex = ''
      // 先赋值让 Vue 惰性生成响应式代理,再读一次把同一代理传给 manager
      await this.uploadMgr.start(file, this.upload)
    },
    pauseUpload() { this.uploadMgr.pause() },
    resumeUpload() { this.uploadMgr.resume() },
    cancelUpload() {
      const u = this.upload
      if (!u) return
      this.uploadMgr.cancel()
      u.phase = 'cancelled'
      u.phaseText = '已取消'
      u.running = false
      u.done = true
      this.sessionKeyFp = ''
      this.verified = 0
      this.totalChunks = 0
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
      // 先赋值让 Vue 惰性生成响应式代理,再读一次把同一代理传给 manager
      await this.downloadMgr.download(f, rec, this.downloads[f.id])
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
