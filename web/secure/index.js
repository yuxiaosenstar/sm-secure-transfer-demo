/**
 * 请求加密库 —— 唯一对外入口。
 *
 * 把「加密传输」全部能力收拢为门面对象:SM2 密钥协商、SM4 分块加解密(Worker)、
 * SM3/Merkle 完整性校验、并发调度与重试、localStorage 密钥管理、REST API 请求。
 * 调用方(如 main.js 的 Vue 组件)只与 createSecureClient() 返回的对象交互,
 * 不感知内部模块拆分(http/worker-client/scheduler/keystore/manager/crypto)。
 *
 * 与 UI 的边界(回调注入,库不 import 组件):
 *  - onSession(patch|fn)    协议条等组件自有状态同步(函数式支持 stage max 语义)
 *  - onFilesChanged()       文件列表刷新(completeUpload 后保持顺序)
 *  - onDownloadEnd(id)      下载行保留数秒后清理
 *  - getPubkey()            返回组件持有的服务端 SM2 公钥(上传封装会话密钥用)
 *
 * 任务对象采用"代理写入"模式:组件创建任务对象先赋值到响应式 data,再把读到的
 * 代理传给 startUpload()/download(),库只写代理的展示字段即触发模板更新。
 * 门面实例应被 markRaw() 后挂到组件 data(防内部 AbortController/Set/Map/scheduler
 * 被 Vue 代理包裹)。
 */
import { api } from './http.js'
import { WorkerClient } from './worker-client.js'
import { UploadManager } from './upload-manager.js'
import { DownloadManager } from './download-manager.js'
import { keyStore } from './keystore.js'
import { formatBytes, formatTime, shortHex } from './format.js'

/**
 * 创建请求加密库门面。
 * @param {object} opts { onSession, onFilesChanged, onDownloadEnd, getPubkey }
 * @returns {object} client:fetchPubkey / listFiles / removeFile / getKey / hasKey /
 *   removeKey / startUpload / pauseUpload / resumeUpload / cancelUpload / download
 */
export function createSecureClient(opts = {}) {
  const { onSession, onFilesChanged, onDownloadEnd, getPubkey } = opts
  // Worker 客户端同步创建:与 mounted 时序一致(第一个 await 前建好,drop 不产生未处理 rejection)
  const worker = new WorkerClient()
  const uploadMgr = new UploadManager(worker, { onSession, onFilesChanged, getPubkey })
  const downloadMgr = new DownloadManager(worker, { onSession, onDownloadEnd })

  return {
    /* ---------- 服务端握手 ---------- */
    /** 拉取服务端 SM2 公钥与指纹,返回 { publicKey, fingerprint }(由调用方赋值) */
    async fetchPubkey() {
      const { publicKey, fingerprint } = await api('/api/pubkey')
      return { publicKey, fingerprint }
    },

    /* ---------- 文件管理 ---------- */
    /** 文件列表;失败返回空数组(与组件侧 try/catch 等价) */
    async listFiles() {
      try { return (await api('/api/files')).files } catch { return [] }
    },
    async removeFile(id) { await api(`/api/files/${id}`, { method: 'DELETE' }) },

    /* ---------- 密钥存储(localStorage) ---------- */
    getKey(id) { return keyStore.get(id) },
    hasKey(id) { return !!keyStore.get(id) },
    removeKey(id) { keyStore.remove(id) },

    /* ---------- 上传编排 ---------- */
    /** display 为组件任务对象的响应式代理(先赋值到 data 再传入) */
    startUpload(file, display) { return uploadMgr.start(file, display) },
    pauseUpload() { uploadMgr.pause() },
    resumeUpload() { uploadMgr.resume() },
    cancelUpload() { uploadMgr.cancel() },

    /* ---------- 下载编排 ---------- */
    /** rec 为 localStorage 密钥记录(组件经 getKey 读出);dl 为任务对象代理 */
    download(f, rec, dl) { return downloadMgr.download(f, rec, dl) },
  }
}

// 展示格式化:模板挂组件用(formatSpeed/formatTimeShort 是库内部依赖,不对外)
export { formatBytes, formatTime, shortHex } from './format.js'
