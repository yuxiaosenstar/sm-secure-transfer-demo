/**
 * 加密/解密 Web Worker(module worker,由 vite 打包)。
 *
 * 所有加解密与 SM3 在 worker-core 中执行,主线程只做调度 —— 大文件处理不阻塞 UI。
 * File 通过结构化克隆一次性传入(共享底层存储,不复制字节),分块读取与加解密
 * 全部在 Worker 内完成;ArrayBuffer 结果用 Transferable 零拷贝回传。
 */
import { selfCheck, createWorkerHandlers } from './worker-core.js'

selfCheck()
// onmessage 回调收到的是 event(消息在 event.data 里),而 createWorkerHandlers 的
// onMessage 期望消息对象本身 —— 必须在此解包,否则 msg.t 恒为 undefined。
const handleMessage = createWorkerHandlers({
  post: (obj, transfer) => self.postMessage(obj, transfer || []),
})
self.onmessage = (e) => handleMessage(e.data)
