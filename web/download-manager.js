/**
 * 下载编排(传输逻辑):流式写盘/内存组装 → 三方完整性核对 → 逐块解密校验。
 *
 * 与 UI 的边界(与 upload-manager 一致):
 *  - 组件创建 dl 任务对象并先赋值到 `this.downloads[f.id]`(响应式),再把读到的
 *    代理经 download() 传给本类,manager 只写代理的 pct/phaseText/phase。
 *  - 协议条字段(sessionKeyFp/verified/totalChunks/rootHex/stage)经 onSession 同步。
 *  - 下载完成后行清理(保留数秒让用户看到结果)委托给组件的 onDownloadEnd(fileId)。
 *  - 解密密钥 rec 由组件从 localStorage 读出传入(manager 不关心密钥从哪来)。
 *
 * 手势限制:`window.showSaveFilePicker` 必须是本方法第一个同步调用 —— 浏览器
 * 要求保存对话框在用户手势(点击下载按钮)内打开,此前不能有任何 await。
 */
import { fetchWithTimeout, api } from './http.js'
import { ChunkScheduler, NonRetryable } from './scheduler.js'
import { WorkerClient } from './worker-client.js'
import * as SM from './shared/crypto.js'

export class DownloadManager {
  /**
   * @param {WorkerClient} worker 与 UI 共享的 worker 客户端(mounted 同步创建)
   * @param {object} cb { onSession(patch|fn), onDownloadEnd(fileId) }
   */
  constructor(worker, cb) {
    this.worker = worker
    this.cb = cb
    this.display = null // 组件下载任务的响应式代理
  }

  /**
   * @param {object} f 文件行 { id, name, ... }
   * @param {object} rec 密钥记录 { keyHex, rootHash, name }(组件已读 localStorage)
   * @param {object} dl 下载任务对象的响应式代理
   */
  async download(f, rec, dl) {
    this.display = dl

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

      this.cb.onSession({ sessionKeyFp: SM.sm3Hex(SM.hexToBytes(rec.keyHex)), stage: 1, totalChunks: meta.chunkCount, verified: 0 })

      const parts = fsa ? null : new Array(meta.chunkCount)
      const scheduler = this.makeDownloadScheduler(meta, fsa)
      const indices = Array.from({ length: meta.chunkCount }, (_, i) => i)
      const { failed } = await scheduler.run(indices, (i, signal) =>
        this.downloadChunkJob(meta, rec.keyHex, i, signal, parts, writable)
      )
      if (failed.length) throw new Error('下载校验失败: ' + failed.join(', '))

      this.cb.onSession({ rootHex: root, stage: 4, verified: meta.chunkCount })
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
      this.cb.onDownloadEnd(f.id)
    }
  }

  async downloadChunkJob(meta, keyHex, i, signal, parts, writable) {
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
  }

  makeDownloadScheduler(meta, fsa) {
    return new ChunkScheduler({
      concurrency: fsa ? 1 : 4, // 流式写盘必须按序写入
      retries: 3,
      onStatus: (i, state) => {
        if (state === 'failed') this.display.phaseText = '下载出错,自动重试…'
      },
      onProgress: (done) => {
        this.display.pct = meta.chunkCount ? Math.round((done / meta.chunkCount) * 100) : 100
        this.display.phaseText = `解密校验中 ${done}/${meta.chunkCount}`
      },
    })
  }

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
  }
}
