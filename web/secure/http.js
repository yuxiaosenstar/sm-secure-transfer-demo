/**
 * HTTP 请求层:与服务的 REST API 通信的基础设施。
 *
 * 从 main.js 拆分出的传输逻辑之一。api() 封装"取 JSON 响应 / 非 2xx 抛错"的
 * 统一语义;fetchWithTimeout 给每个请求叠加超时;sleep 支持 AbortSignal 中断
 * (调度器退避重试与暂停等待复用)。
 */

/** 请求 REST API:JSON 响应自动解析,非 JSON 返回 null;非 2xx 抛 Error */
export async function api(path, opts = {}) {
  const res = await fetch(path, opts)
  const ct = res.headers.get('content-type') || ''
  const body = ct.includes('application/json') ? await res.json() : null
  if (!res.ok) {
    const detail = body && body.error ? `: ${body.error}` : ''
    throw new Error(`HTTP ${res.status}${detail}`)
  }
  return body
}

/** 可中断延时:signal abort 时抛 AbortError(调度器重试退避/暂停等待用) */
export function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(new DOMException('aborted', 'AbortError'))
    const t = setTimeout(resolve, ms)
    if (signal) signal.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('aborted', 'AbortError')) }, { once: true })
  })
}

/**
 * 带超时的 fetch:外部 signal(暂停/取消)与内部超时信号合并,
 * 任一触发即中止请求。默认每请求 60s 超时,防止悬挂连接卡住调度。
 */
export function fetchWithTimeout(url, opts, signal, ms = 60000) {
  const timeoutSignal = typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(ms) : null
  const combined = signal && timeoutSignal && AbortSignal.any
    ? AbortSignal.any([signal, timeoutSignal])
    : signal || timeoutSignal
  return fetch(url, Object.assign({}, opts, { signal: combined }))
}
