/**
 * Worker 核心逻辑(纯模块,可脱离浏览器直接测试)。
 *
 * 所有加解密与 SM3 的执行体:createWorkerHandlers 产出消息处理器,由宿主注入
 * post 回调 —— worker 里接 self.postMessage,测试里接数组收集。file 状态存于
 * 处理器闭包内,ArrayBuffer 结果经 transfer 参数零拷贝回传。
 *
 * 协议:
 *   in   {t:'set-file', file}                       上传前一次性传入 File
 *   in   {t:'encrypt-chunk', id, index, keyHex}     加密第 index 块(内部 file.slice + arrayBuffer)
 *   out  {t:'chunk-encrypted', id, index, ivHex, ct, ptHashHex}
 *   in   {t:'decrypt-chunk', id, index, keyHex, ivHex, ct, plainLen}
 *   out  {t:'chunk-decrypted', id, index, pt, ptHashHex}
 *   in   {t:'merkle-root', id, chunkHashes[]}
 *   out  {t:'merkle-root-done', id, rootHex}
 *   out  {t:'error', id, message}                   任一任务失败
 */
import * as SM from './crypto.js'

/** 启动自检:SM3 公开测试向量,校验库加载与双端字节语义 */
export function selfCheck() {
  const KAT = SM.sm3Hex(new TextEncoder().encode('abc'))
  if (KAT !== '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0') {
    throw new Error('sm-crypto 自检失败:sm3("abc") = ' + KAT)
  }
}

/**
 * 创建消息处理器。post(obj, transfer?) 由宿主注入。
 * 返回 onMessage(msg):同步错误统一回 {t:'error', ...}(异步读取失败在 handleEncrypt 内回)。
 */
export function createWorkerHandlers({ post }) {
  let file = null // 仅上传流程使用

  function handleEncrypt(msg) {
    if (!file) throw new Error('未设置文件')
    const index = msg.index
    const off = index * SM.CHUNK_SIZE
    const len = Math.min(SM.CHUNK_SIZE, file.size - off)
    if (len <= 0) throw new Error('块索引越界: ' + index)

    // 注意:file 是主线程 postMessage 结构化克隆过来的,Worker 里 slice().arrayBuffer()
    // 读取的是共享底层存储(不复制整文件字节)。读取与加密都是异步的,所以这里用
    // promise 链而非同步 throw —— 同步 throw 只能被外层 onMessage 的 try/catch 捕获,
    // 而异步失败必须显式走 .then 的第二个回调把 error 消息回传,否则主线程的
    // 请求会永久挂起(主线程 pending 等待超时才报错)。
    file.slice(off, off + len).arrayBuffer().then(
      (buf) => {
        const plain = new Uint8Array(buf)
        const res = SM.chunkEncrypt(msg.keyHex, plain)
        post(
          {
            t: 'chunk-encrypted',
            id: msg.id,
            index,
            ivHex: res.ivHex,
            ct: res.ct,
            ptHashHex: res.ptHashHex,
          },
          [res.ct.buffer]
        )
      },
      (e) => {
        post({ t: 'error', id: msg.id, message: '读取分块失败: ' + e })
      }
    )
  }

  function handleDecrypt(msg) {
    const res = SM.chunkDecrypt(msg.keyHex, msg.ivHex, msg.ct, msg.plainLen)
    post(
      {
        t: 'chunk-decrypted',
        id: msg.id,
        index: msg.index,
        pt: res.plain,
        ptHashHex: res.ptHashHex,
      },
      [res.plain.buffer]
    )
  }

  return function onMessage(msg) {
    try {
      switch (msg.t) {
        case 'set-file':
          file = msg.file
          break
        case 'encrypt-chunk':
          handleEncrypt(msg)
          break
        case 'decrypt-chunk':
          handleDecrypt(msg)
          break
        case 'merkle-root':
          post({ t: 'merkle-root-done', id: msg.id, rootHex: SM.merkleRoot(msg.chunkHashes) })
          break
        default:
          throw new Error('未知任务类型: ' + msg.t)
      }
    } catch (e) {
      post({ t: 'error', id: msg && msg.id, message: String((e && e.message) || e) })
    }
  }
}
