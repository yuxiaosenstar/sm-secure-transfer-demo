/**
 * Worker 客户端:把"发任务 → 等回包"封装成 Promise。
 *
 * 协议是请求-响应关联的:每次 call 分配自增 id 写入消息,worker 的回传消息
 * 必须原样带上该 id(见 worker-core.js 的协议注释),onmessage 据此把回包
 * 路由到对应的 pending Promise。消息类型约定:
 *   out {t:'chunk-encrypted'|'chunk-decrypted'|'merkle-root-done'} 成功
 *   out {t:'error', message}  失败 → reject
 * 若 worker 侧异常导致消息永远不会回来,call 的 Promise 就会永久 pending ——
 * 这是调度器 job 超时(每块 60s)兜底的对象。
 */
export class WorkerClient {
  constructor() {
    this.worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
    this.pending = new Map()
    this.seq = 0
    this.worker.onmessage = (ev) => {
      const m = ev.data
      const p = this.pending.get(m.id)
      if (!p) return // 无关联请求的消息(理论上只可能是调试残留)静默丢弃
      this.pending.delete(m.id)
      m.t === 'error' ? p.reject(new Error(m.message)) : p.resolve(m)
    }
    this.worker.onerror = (ev) => {
      // worker 崩溃/未捕获异常:让所有在途请求失败,而不是永久挂起
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
