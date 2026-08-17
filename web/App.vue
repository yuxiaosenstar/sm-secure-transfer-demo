<template>
  <div id="app">
    <!-- 顶栏 -->
    <header class="top">
      <div class="brand">
        <div class="brand-mark">SM</div>
        <div>
          <h1>国密文件柜</h1>
          <p class="sub">SM2 密钥封装 · SM4-CBC 分块加密 · SM3 完整性校验 · Web Worker 大文件支持</p>
        </div>
      </div>
      <div class="fingerprint" :title="'SM2 公钥:' + pubkey" @click="copyPubkey">
        <span class="fp-label">SM2 公钥指纹 · 点击复制</span>
        <span class="fp-value">{{ fingerprint || '…' }}</span>
      </div>
    </header>

    <!-- 协议条:实时显示加密管线的真实状态 -->
    <section class="protocol" aria-label="加密流程状态">
      <div class="stage" :class="stageClass(0)">
        <div class="st-name">SM2 密钥封装</div>
        <div class="st-val"><span class="st-dot"></span>{{ stageVal(0) }}</div>
      </div>
      <div class="p-arrow">→</div>
      <div class="stage" :class="stageClass(1)">
        <div class="st-name">SM4 会话密钥</div>
        <div class="st-val"><span class="st-dot"></span>{{ stageVal(1) }}</div>
      </div>
      <div class="p-arrow">→</div>
      <div class="stage" :class="stageClass(2)">
        <div class="st-name">SM3 逐块校验</div>
        <div class="st-val"><span class="st-dot"></span>{{ stageVal(2) }}</div>
      </div>
      <div class="p-arrow">→</div>
      <div class="stage" :class="stageClass(3)">
        <div class="st-name">Merkle 根比对</div>
        <div class="st-val"><span class="st-dot"></span>{{ stageVal(3) }}</div>
      </div>
    </section>

    <main>
      <!-- 通知条 -->
      <div v-if="notice" class="notice" :class="notice.type" role="alert">
        {{ notice.text }}
        <button class="notice-close" @click="notice = null" aria-label="关闭">×</button>
      </div>

      <!-- 上传区 -->
      <section class="card">
        <div
          class="zone"
          role="button" tabindex="0"
          :class="{ dragover: dragover }"
          @click="pickFile" @keydown.enter="pickFile" @keydown.space.prevent="pickFile"
          @dragover.prevent="dragover = true"
          @dragleave.prevent="dragover = false"
          @drop.prevent="onDrop"
        >
          <div class="zone-icon">⇪</div>
          <p class="zone-title">拖入文件,或点击选择</p>
          <p class="zone-sub">4 MiB / 块 · Worker 后台分块加密 · 传输失败自动重试、可暂停续传</p>
          <input type="file" ref="fileInput" hidden @change="onPick" />
        </div>

        <!-- 传输面板 -->
        <div v-if="upload" class="transfer">
          <div class="tf-head">
            <span class="tf-name">{{ upload.name }}</span>
            <span class="tf-phase" :class="phaseCls(upload)">{{ upload.phaseText }}</span>
          </div>
          <div class="bar"><div class="bar-fill" :style="{ width: upload.pct + '%' }"></div></div>
          <div class="tf-stats">
            <span>进度 <b>{{ upload.doneBytes }}</b> / <b>{{ upload.totalBytes }}</b></span>
            <span v-if="upload.speed">速度 <b>{{ upload.speed }}</b></span>
            <span v-if="upload.eta">剩余 <b>{{ upload.eta }}</b></span>
            <span>已验 <b>{{ upload.verified }} / {{ upload.chunkCount }}</b> 块</span>
          </div>
          <div class="matrix-wrap" v-if="upload.chunkCells.length">
            <div class="matrix-cap">
              <span>分块状态 · 共 {{ upload.chunkCount }} 块</span>
              <span>橙=加密/传输 · 绿=已验</span>
            </div>
            <div class="matrix">
              <div
                v-for="c in upload.chunkCells" :key="c.i"
                class="cell" :class="cellCls(c.state)"
                :title="'块 ' + c.i + ':' + cellName(c.state)"
              ></div>
            </div>
          </div>
          <div class="tf-actions">
            <button v-if="upload.running" @click="pauseUpload">暂停</button>
            <button v-else-if="!upload.done" @click="resumeUpload">继续</button>
            <button v-if="!upload.done" class="danger" @click="cancelUpload">取消</button>
          </div>
        </div>
      </section>

      <!-- 文件列表 -->
      <section class="card files-card">
        <div class="card-head">
          <h2>文件柜</h2>
          <span class="count mono">{{ files.length }} 个文件</span>
        </div>
        <div v-if="!files.length" class="empty">还没有文件 —— 上传一个试试</div>
        <table v-else>
          <thead>
            <tr>
              <th>名称</th><th>大小</th><th>块数</th><th>完整性</th><th>上传时间</th><th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="f in files" :key="f.id" :data-id="f.id">
              <td class="f-name">
                {{ f.name }}
                <span v-if="!hasKey(f.id)" class="keyless">(本浏览器无密钥)</span>
              </td>
              <td class="f-meta">{{ formatBytes(f.size) }}</td>
              <td class="f-meta">{{ f.chunkCount }}</td>
              <td><span class="badge" :class="hasKey(f.id) ? 'ok' : 'dim'">✓ {{ hasKey(f.id) ? '可解密' : '密文' }}</span></td>
              <td class="f-meta">{{ formatTime(f.createdAt) }}</td>
              <td>
                <div class="row-actions">
                  <template v-if="dl = downloads[f.id]">
                    <div class="row-progress" style="min-width:180px">
                      <div class="bar"><div class="bar-fill" :style="{ width: dl.pct + '%' }"></div></div>
                      <span class="mono">{{ dl.phaseText }}</span>
                    </div>
                  </template>
                  <template v-else>
                    <button @click="download(f)" :disabled="busy(f)">下载</button>
                    <button class="danger" @click="remove(f)" :disabled="busy(f)">删除</button>
                  </template>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>

    <footer>
      <b>说明</b> 文件在浏览器内以 4 MiB 分块、每块独立随机 IV 的 SM4-CBC 加密,密文落盘于服务端,明文与密钥不落盘;完整性由逐块 SM3 与 Merkle 根双重校验,下载时若内容被篡改将直接报错。<br />
      <b>局限</b> 生产环境应叠加 TLS;解密密钥保存在本浏览器 localStorage(刷新后可解,换浏览器则无法解密);Firefox 不支持流式写盘,大文件下载走内存组装。
    </footer>
  </div>
</template>

<script>
/**
 * 根组件(Vue SFC):模板 + 全局样式 + 组件逻辑。
 *
 * 职责边界:App.vue 只保留 UI 状态与事件委托;上传/下载的传输编排
 * (密钥协商、分块调度、重试对账、Merkle 校验、写盘)全部封装在
 * web/secure/ 请求加密库中,经 createSecureClient() 门面与回调与本组件通信
 * (详见 secure/index.js 的库边界注释)。
 *
 * 通信方式:组件创建任务对象先赋值到响应式 data,再把读到的代理传给 manager;
 * manager 只写代理的展示字段即触发模板更新。组件自有状态经回调注入:
 *  - onSession(patch|fn)  协议条同步(函数式支持 stage max 语义)
 *  - onFilesChanged()     文件列表刷新(completeUpload 后保持顺序)
 *  - onDownloadEnd(id)    下载行保留数秒后清理
 *  - getPubkey()          上传 SM2 封装用的服务端公钥
 *
 * 兼容红线:模板所有绑定与 smoke 脚本的
 * window.__smApp.upload / pauseUpload() / resumeUpload() 原样保留。
 */
import { markRaw } from 'vue'
import { createSecureClient, formatBytes, formatTime, shortHex } from './secure/index.js'

export default {
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
      // markRaw 包住库门面:防内部 AbortController/Set/Map/scheduler 被代理包裹
      client: null,
    }
  },
  computed: {
    session() { return this.sessionKeyFp ? shortHex(this.sessionKeyFp) : '—' },
  },
  async mounted() {
    window.__smApp = this // 调试钩子:供 CDP/控制台直接访问组件实例
    // 库门面必须在第一个 await 前同步建好(内部同步创建 Worker),否则 mounted 期间
    // drop 会产生未处理 rejection
    this.client = markRaw(createSecureClient({
      onSession: (p) => Object.assign(this, typeof p === 'function' ? p(this) : p),
      onFilesChanged: () => this.refreshFiles(),
      // 保留数秒让用户看到结果,随后恢复按钮
      onDownloadEnd: (fileId) => setTimeout(() => { delete this.downloads[fileId] }, 8000),
      getPubkey: () => this.pubkey,
    }))
    await this.refreshFiles()
    try {
      const { publicKey, fingerprint } = await this.client.fetchPubkey()
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
      // 先赋值让 Vue 惰性生成响应式代理,再读一次把同一代理传给库门面
      await this.client.startUpload(file, this.upload)
    },
    pauseUpload() { this.client.pauseUpload() },
    resumeUpload() { this.client.resumeUpload() },
    cancelUpload() {
      const u = this.upload
      if (!u) return
      this.client.cancelUpload()
      u.phase = 'cancelled'
      u.phaseText = '已取消'
      u.running = false
      u.done = true
      this.sessionKeyFp = ''
      this.verified = 0
      this.totalChunks = 0
    },

    /* ---------- 下载 ---------- */
    hasKey(id) { return this.client.hasKey(id) },
    busy(f) { return !!this.downloads[f.id] },

    async download(f) {
      const rec = this.client.getKey(f.id)
      if (!rec) {
        this.notify('此浏览器没有该文件的解密密钥。密钥只保存在上传时的那台浏览器(刷新后仍可解),换设备或清除站点数据后将无法解密。')
        return
      }
      const dl = { pct: 0, phaseText: '准备中…', phase: 'init' }
      this.downloads[f.id] = dl
      // 先赋值让 Vue 惰性生成响应式代理,再读一次把同一代理传给库门面
      await this.client.download(f, rec, this.downloads[f.id])
    },

    /* ---------- 文件管理 ---------- */
    async refreshFiles() {
      this.files = await this.client.listFiles()
    },
    async remove(f) {
      if (!confirm(`删除「${f.name}」?删除后不可恢复。`)) return
      await this.client.removeFile(f.id)
      this.client.removeKey(f.id)
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
}
</script>

<style>
  :root {
    --bg: #0d141b;
    --panel: #131d27;
    --panel-2: #182430;
    --line: #24313d;
    --line-strong: #33424f;
    --text: #e9e4d8;
    --dim: #8b98a4;
    --faint: #5d6b78;
    --signal: #f0904a;
    --ok: #7fb385;
    --alert: #e35d5d;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans SC", "Segoe UI", sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { color-scheme: dark; }
  body {
    font-family: var(--sans);
    background: var(--bg);
    background-image:
      radial-gradient(1100px 480px at 18% -10%, rgba(240, 144, 74, 0.07), transparent 60%),
      radial-gradient(900px 420px at 85% 0%, rgba(127, 179, 133, 0.05), transparent 55%);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.55;
  }
  .mono { font-family: var(--mono); }
  #app { max-width: 1080px; margin: 0 auto; padding: 28px 24px 64px; }
  button {
    font-family: inherit; font-size: 13px; color: var(--text);
    background: var(--panel-2); border: 1px solid var(--line-strong);
    border-radius: 8px; padding: 6px 14px; cursor: pointer; transition: border-color .15s, background .15s, color .15s;
  }
  button:hover:not(:disabled) { border-color: var(--signal); color: var(--signal); }
  button:disabled { opacity: .4; cursor: not-allowed; }
  button:focus-visible, .zone:focus-visible { outline: 2px solid var(--signal); outline-offset: 2px; }
  button.danger:hover:not(:disabled) { border-color: var(--alert); color: var(--alert); }
  button.primary { background: var(--signal); color: #1a120b; border-color: transparent; font-weight: 600; }
  button.primary:hover:not(:disabled) { background: #f5a05e; color: #1a120b; }

  /* ---------- 顶栏 ---------- */
  .top { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding-bottom: 22px; }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand-mark {
    width: 44px; height: 44px; border-radius: 12px; flex: none;
    background: linear-gradient(135deg, var(--signal), #b96a2e);
    color: #1a120b; font-family: var(--mono); font-weight: 700; font-size: 16px;
    display: grid; place-items: center; letter-spacing: -0.5px;
    box-shadow: 0 4px 18px rgba(240, 144, 74, 0.25);
  }
  h1 { font-size: 22px; letter-spacing: -0.02em; line-height: 1.2; }
  .sub { color: var(--dim); font-size: 12.5px; margin-top: 2px; }
  .fingerprint {
    display: flex; flex-direction: column; align-items: flex-end; gap: 3px;
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 8px 14px;
  }
  .fp-label { font-size: 10.5px; color: var(--faint); letter-spacing: 0.08em; }
  .fp-value { font-size: 12px; color: var(--dim); letter-spacing: 0.14em; cursor: copy; }
  .fp-value:hover { color: var(--signal); }

  /* ---------- 协议条 ---------- */
  .protocol {
    display: grid; grid-template-columns: 1fr auto 1fr auto 1fr auto 1fr;
    align-items: stretch; gap: 0;
    background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
    padding: 14px 18px; margin-bottom: 20px;
  }
  .p-arrow { color: var(--faint); font-size: 15px; align-self: center; padding: 0 12px; }
  .stage { min-width: 0; }
  .stage .st-name { font-size: 11.5px; font-weight: 600; color: var(--faint); letter-spacing: 0.04em; }
  .stage .st-val { font-family: var(--mono); font-size: 12px; margin-top: 4px; color: var(--dim); word-break: break-all; display: flex; align-items: center; gap: 6px; }
  .stage .st-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--line-strong); flex: none; }
  .stage.active .st-name { color: var(--signal); }
  .stage.active .st-dot { background: var(--signal); box-shadow: 0 0 0 0 rgba(240,144,74,.5); animation: pulse 1.6s infinite; }
  .stage.done .st-name { color: var(--ok); }
  .stage.done .st-dot { background: var(--ok); }
  .stage.done .st-val { color: var(--ok); }
  .stage.error .st-name { color: var(--alert); }
  .stage.error .st-dot { background: var(--alert); }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(240,144,74,.45); }
    70% { box-shadow: 0 0 0 6px rgba(240,144,74,0); }
    100% { box-shadow: 0 0 0 0 rgba(240,144,74,0); }
  }

  /* ---------- 卡片 ---------- */
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; margin-bottom: 20px; }
  .notice {
    display: flex; align-items: center; gap: 10px;
    border-radius: 10px; padding: 10px 14px; margin-bottom: 16px;
    font-size: 13px; border: 1px solid;
  }
  .notice.error { color: var(--alert); border-color: rgba(227,93,93,.4); background: rgba(227,93,93,.08); }
  .notice.info { color: var(--signal); border-color: rgba(240,144,74,.4); background: rgba(240,144,74,.08); }
  .notice-close { margin-left: auto; padding: 0 6px; font-size: 16px; line-height: 1; border: none; background: none; color: inherit; }
  .notice-close:hover { color: var(--text); }
  .zone {
    border: 1.6px dashed var(--line-strong); border-radius: 12px;
    padding: 42px 20px; text-align: center; cursor: pointer;
    transition: border-color .18s, background .18s;
    background: transparent;
  }
  .zone:hover, .zone.dragover { border-color: var(--signal); background: rgba(240, 144, 74, 0.05); }
  .zone-icon { font-size: 26px; color: var(--signal); margin-bottom: 8px; }
  .zone-title { font-size: 15px; font-weight: 600; }
  .zone-sub { font-size: 12px; color: var(--dim); margin-top: 5px; }

  /* ---------- 传输卡片 ---------- */
  .transfer { padding: 18px 20px 20px; border-top: 1px solid var(--line); }
  .tf-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .tf-name { font-size: 14.5px; font-weight: 600; word-break: break-all; }
  .tf-phase { font-size: 12px; color: var(--signal); }
  .tf-phase.done { color: var(--ok); }
  .tf-phase.error { color: var(--alert); }
  .bar { height: 8px; border-radius: 5px; background: var(--panel-2); margin: 12px 0 10px; overflow: hidden; }
  .bar-fill {
    height: 100%; width: 0%;
    background: linear-gradient(90deg, #b96a2e, var(--signal));
    border-radius: 5px; transition: width .3s ease;
  }
  .tf-stats { display: flex; gap: 18px; font-size: 12px; color: var(--dim); flex-wrap: wrap; }
  .tf-stats b { font-family: var(--mono); font-weight: 600; color: var(--text); }
  .tf-actions { display: flex; gap: 8px; margin-top: 12px; }
  .matrix-wrap { margin-top: 14px; }
  .matrix-cap { font-size: 11px; color: var(--faint); margin-bottom: 8px; display: flex; justify-content: space-between; }
  .matrix {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(9px, 1fr));
    gap: 3px;
  }
  .cell { aspect-ratio: 1; border-radius: 2px; background: var(--panel-2); border: 1px solid var(--line); transition: background .25s, border-color .25s; }
  .cell.encrypting { background: rgba(240,144,74,.35); border-color: var(--signal); }
  .cell.uploading { background: var(--signal); border-color: var(--signal); }
  .cell.retrying { background: rgba(227,93,93,.35); border-color: var(--alert); }
  .cell.verified { background: rgba(127,179,133,.35); border-color: var(--ok); }
  .cell.failed { background: var(--alert); border-color: var(--alert); }
  .cell.skipped { background: transparent; border-color: var(--line); }

  /* ---------- 文件表 ---------- */
  .card-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid var(--line); }
  .card-head h2 { font-size: 14px; letter-spacing: 0.02em; }
  .count { color: var(--faint); font-size: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; font-size: 11px; font-weight: 500; color: var(--faint);
    letter-spacing: 0.06em; padding: 10px 20px; border-bottom: 1px solid var(--line);
  }
  td { padding: 12px 20px; font-size: 13px; border-bottom: 1px solid var(--line); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tbody tr { transition: background .12s; }
  tbody tr:hover { background: var(--panel-2); }
  .f-name { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .f-name .keyless { color: var(--faint); font-size: 11px; margin-left: 8px; }
  .f-meta { font-family: var(--mono); font-size: 12px; color: var(--dim); }
  .badge {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 11.5px; padding: 3px 9px; border-radius: 20px; border: 1px solid;
  }
  .badge.ok { color: var(--ok); border-color: rgba(127,179,133,.4); background: rgba(127,179,133,.08); }
  .badge.dim { color: var(--dim); border-color: var(--line-strong); }
  .badge.error { color: var(--alert); border-color: rgba(227,93,93,.4); background: rgba(227,93,93,.08); }
  .row-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .row-progress { display: flex; align-items: center; gap: 10px; }
  .row-progress .bar { flex: 1; margin: 0; height: 6px; }
  .row-progress .mono { font-size: 11.5px; color: var(--dim); white-space: nowrap; }
  .empty { padding: 46px 20px; text-align: center; color: var(--faint); font-size: 13.5px; }

  footer { margin-top: 30px; font-size: 11.5px; color: var(--faint); line-height: 1.8; }
  footer b { color: var(--dim); font-weight: 600; }

  @media (max-width: 720px) {
    .protocol { grid-template-columns: 1fr; gap: 10px; }
    .p-arrow { display: none; }
    .fingerprint { align-items: flex-start; }
    #app { padding: 20px 14px 48px; }
  }
  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
  }
</style>
