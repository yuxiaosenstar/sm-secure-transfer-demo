/**
 * 通用分块调度器:并发槽位 + 重试退避 + 暂停/取消。
 *
 * 上传与下载共用(上传 3 并发、下载流式写盘 1 并发/内存组装 4 并发)。
 * job(i, signal) 是幂等任务:网络类错误抛出以重试;确定性 4xx/校验失败抛
 * NonRetryable 快速失败。run() 结束时返回 { failed: [indexes], cancelled }。
 */
import { sleep } from './http.js'

/** 重试退避间隔(毫秒):第 n 次重试等待 RETRY_BACKOFF[n],超出取末位 */
const RETRY_BACKOFF = [1000, 3000, 8000]

/** 确定性失败:服务端已明确拒绝(如 4xx 校验失败),重试结果必然相同 → 不重试 */
class NonRetryable extends Error {}

class ChunkScheduler {
  /**
   * @param {object} opts { concurrency, retries, onStatus(i, state), onProgress(done) }
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
  /**
   * 状态机:任务队列(indexes)+ 在途集合(inFlight)+ 暂停/取消标志。
   * 每个在途任务完成时(无论成败)都触发 maybeSettle + pump:maybeSettle 判断
   * 是否全部终结(队列空且无在途),pump 则继续补充下一个任务 —— 因此并发槽位
   * 被占满时,一个任务结束立即由下一个顶上,吞吐不因调度空转而损失。
   */
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
  /**
   * 单个块的任务循环:成功立即返回;失败按指数退避(1s/3s/8s)重试,
   * NonRetryable(服务端确定性拒绝,如 4xx 校验失败)不重试直接判失败。
   * 重试复用同一 job 调用 —— 上传侧因 cipherCache 缓存同一密文而幂等,
   * 下载侧每次重新下载,天然可重试。
   */
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
    this.abort.abort() // 中止所有在途 fetch(job 收到 abort 信号立即抛 AbortError)
    this.maybeSettle()
  }
}

export { ChunkScheduler, NonRetryable, RETRY_BACKOFF }
