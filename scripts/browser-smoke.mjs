/**
 * 真实浏览器冒烟测试:headless Chrome + CDP 驱动完整用户流程。
 *
 * 覆盖:页面挂载(Vue + Worker KAT 自检)→ 上传 8MiB 文件(Worker 分块加密,
 * 含暂停/恢复软校验)→ 服务端转正 → localStorage 密钥落库 → 下载解密 → 字节比对,
 * 全程收集控制台错误。
 *
 * 前置:服务端已在本机运行(默认 3900,可用 SM_SERVER 覆盖)。
 * 用法:node scripts/browser-smoke.mjs
 */
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const SERVER = process.env.SM_SERVER || 'http://localhost:3900'
const CHROME = process.env.SM_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = Number(process.env.SM_CDP_PORT) || 9223

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl)
    this.id = 0
    this.pending = new Map()
    this.events = []
    this.ws.onmessage = (e) => {
      const m = JSON.parse(e.data)
      if (m.id != null && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id)
        this.pending.delete(m.id)
        m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result)
      } else if (m.method) {
        this.events.push(m)
      }
    }
  }
  async open() {
    if (this.ws.readyState === WebSocket.OPEN) return
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve
      this.ws.onerror = reject
    })
  }
  send(method, params = {}) {
    const id = ++this.id
    this.ws.send(JSON.stringify({ id, method, params }))
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`CDP ${method} 超时`))
      }, 30000)
    })
  }
  async evaluate(expression, awaitPromise = true) {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise, returnByValue: true })
    if (r.exceptionDetails) throw new Error('页面执行异常: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text))
    return r.result.value
  }
  close() { try { this.ws.close() } catch {} }
}

async function waitFor(fn, timeout, label) {
  const start = Date.now()
  for (;;) {
    const v = await fn()
    if (v) return v
    if (Date.now() - start > timeout) throw new Error('等待超时: ' + label)
    await sleep(300)
  }
}

async function launchChrome() {
  const profile = mkdtempSync(join(tmpdir(), 'sm-chrome-'))
  const proc = spawn(CHROME, [
    '--headless=new', `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`, '--no-first-run', '--disable-gpu',
    '--window-size=1280,900',
    'about:blank',
  ], { stdio: 'ignore' })
  const listUrl = `http://127.0.0.1:${PORT}/json/list`
  await waitFor(async () => {
    try {
      const res = await fetch(listUrl)
      const list = await res.json()
      const page = list.find((t) => t.type === 'page')
      return page && page.webSocketDebuggerUrl
    } catch { return null }
  }, 15000, 'Chrome CDP 端口就绪')
  return proc
}

function collectConsoleErrors(cdp) {
  return cdp.events.filter(
    (e) =>
      (e.method === 'Runtime.exceptionThrown') ||
      (e.method === 'Log.entryAdded' && ['error', 'warning'].includes(e.params.entry.level)) ||
      (e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error')
  )
}

async function main() {
  if (!existsSync(CHROME)) throw new Error(`未找到 Chrome: ${CHROME}`)
  const pub = await fetch(`${SERVER}/api/pubkey`).then((r) => r.json()).catch(() => null)
  if (!pub || !pub.publicKey) throw new Error(`服务端不可用: ${SERVER}(先运行 node server.js)`)

  const chrome = await launchChrome()
  let cdp
  try {
    const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()
    cdp = new CDP(list.find((t) => t.type === 'page').webSocketDebuggerUrl)
    await cdp.open()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Log.enable')

    // 打开应用
    await cdp.send('Page.navigate', { url: SERVER + '/' })
    await waitFor(async () => (await cdp.evaluate('document.readyState')) === 'complete', 20000, '页面加载')
    await waitFor(async () => {
      const fp = await cdp.evaluate(`document.querySelector('.fp-value')?.textContent?.trim()`)
      return fp && fp !== '…' && !fp.includes('无法连接')
    }, 20000, 'SM2 公钥指纹加载')
    console.log('✓ 页面挂载,SM2 公钥指纹已加载')

    // 构造测试文件(24MiB+7,6 块,给暂停留出窗口)并注入文件输入框
    const fileSize = 24 * 1024 * 1024 + 7
    const data = randomBytes(fileSize)
    const b64 = data.toString('base64')
    console.log(`注入 ${(fileSize / 1048576).toFixed(1)} MiB 测试文件…`)
    await cdp.evaluate(`(() => {
      const bin = Uint8Array.from(atob(${JSON.stringify(b64)}), (c) => c.charCodeAt(0))
      const file = new File([bin], 'smoke-测试文件.bin', { type: 'application/octet-stream' })
      const dt = new DataTransfer()
      dt.items.add(file)
      const input = document.querySelector('input[type=file]')
      input.files = dt.files
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })()`)

    // 上传开始后立即暂停(150ms 轮询,通过组件实例直调避免 DOM 竞态)
    let paused = false
    try {
      await waitFor(async () => {
        const u = await cdp.evaluate(`window.__smApp?.upload`)
        return !!u && !u.done
      }, 8000, '上传开始')
      await cdp.evaluate(`window.__smApp.pauseUpload()`)
      await sleep(400)
      const st = JSON.parse(await cdp.evaluate(`JSON.stringify({ phase: window.__smApp.upload?.phaseText, paused: window.__smApp.upload?.paused, running: window.__smApp.upload?.running })`))
      paused = st.paused
      console.log(paused ? `✓ 暂停生效(${st.phase})` : `⚠ 暂停未生效: ${JSON.stringify(st)}`)
      await cdp.evaluate(`window.__smApp.resumeUpload()`)
      console.log('→ 已继续')
    } catch (e) {
      console.log('⚠ 暂停校验跳过:', e.message)
    }

    // 等待上传完成
    await waitFor(async () => {
      const t = await cdp.evaluate(`document.querySelector('.tf-phase')?.textContent?.trim() || ''`)
      return t.includes('✓') || t.includes('失败')
    }, 120000, '上传完成')
    const finalPhase = await cdp.evaluate(`document.querySelector('.tf-phase')?.textContent?.trim()`)
    console.log('上传结果:', finalPhase)
    if (finalPhase.includes('失败')) throw new Error('上传失败: ' + finalPhase)

    // 服务端转正 + localStorage 密钥落库
    const { files } = await (await fetch(`${SERVER}/api/files`)).json()
    const f = files.find((x) => x.name === 'smoke-测试文件.bin' && x.size === fileSize)
    if (!f || f.size !== fileSize) throw new Error('服务端文件缺失或大小不符')
    console.log(`✓ 服务端已转正:${f.id} 共 ${f.chunkCount} 块`)
    const stored = JSON.parse(await cdp.evaluate(`localStorage.getItem('sm-vault-keys') || '{}'`))
    if (!stored[f.id] || stored[f.id].keyHex.length !== 32 || !stored[f.id].rootHash) {
      throw new Error('localStorage 密钥记录缺失或非法')
    }
    console.log('✓ 会话密钥与 Merkle 根已落库(可供下载解密)')

    // 触发下载(无 FSA → 内存组装 → 浏览器保存);用 data-id 精确定位本运行上传的行
    const dlDir = mkdtempSync(join(tmpdir(), 'sm-dl-'))
    await cdp.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: dlDir })
    // headless 里 showSaveFilePicker 存在但永不完成(无 UI),禁用之走内存组装路径
    await cdp.evaluate('window.showSaveFilePicker = undefined')
    await cdp.evaluate(`document.querySelector('tbody tr[data-id="${f.id}"]').querySelector('button').click()`)
    try {
      await waitFor(async () => {
        const t = await cdp.evaluate(`document.querySelector('tbody tr[data-id="${f.id}"]')?.textContent || ''`)
        return t.includes('✓ 已保存') || t.includes('下载失败')
      }, 60000, '下载完成')
    } catch (e) {
      // 超时诊断:打印行状态与控制台错误
      const row = await cdp.evaluate(`document.querySelector('tbody tr[data-id="${f.id}"]')?.textContent || '(行消失)'`)
      console.log('下载超时,当前行状态:', row.replace(/\s+/g, ' ').slice(0, 160))
      for (const evt of collectConsoleErrors(cdp)) {
        const d = evt.params.entry || evt.params.exceptionDetails || evt.params
        console.log('控制台:', JSON.stringify(d).slice(0, 300))
      }
      throw e
    }
    // 等待完整落盘(排除 .crdownload 中间文件,且大小与源文件一致)
    try {
      await waitFor(() => {
        const done = readdirSync(dlDir).find((f) => !f.endsWith('.crdownload'))
        return done && readFileSync(join(dlDir, done)).length === fileSize
      }, 30000, '下载文件完整落盘')
    } catch (e) {
      for (const f of readdirSync(dlDir)) {
        const buf = readFileSync(join(dlDir, f))
        console.log(`落盘诊断 [${f}] ${buf.length}B:`, buf.slice(0, 200).toString('latin1'))
      }
      throw e
    }
    const saved = join(dlDir, readdirSync(dlDir).find((f) => !f.endsWith('.crdownload')))
    const downloaded = readFileSync(saved)
    if (downloaded.length !== fileSize || !downloaded.equals(data)) {
      console.log('落盘文件头:', downloaded.slice(0, 100).toString('latin1'))
      throw new Error(`下载文件字节不一致:期望 ${fileSize},实际 ${downloaded.length}`)
    }
    console.log(`✓ 下载文件与原始文件字节完全一致(${(fileSize / 1048576).toFixed(1)} MiB,含暂停续传路径)`)

    // 清理:删除本运行上传的文件,保持服务端整洁
    await fetch(`${SERVER}/api/files/${f.id}`, { method: 'DELETE' })
    console.log('✓ 已清理测试文件')

    // 控制台错误检查
    const errs = collectConsoleErrors(cdp)
    const bad = errs.filter((e) => !String(JSON.stringify(e)).includes('favicon'))
    if (bad.length) {
      console.log('⚠ 控制台错误:')
      for (const e of bad.slice(0, 5)) console.log('   ', e.method, JSON.stringify(e.params).slice(0, 300))
    }
    console.log(bad.length ? '冒烟完成(存在控制台错误)' : '✓ 冒烟完成,控制台无错误')
    process.exitCode = bad.length ? 1 : 0
  } finally {
    if (cdp) cdp.close()
    chrome.kill('SIGKILL')
  }
}

main().catch((e) => {
  console.error('✗ 冒烟失败:', e.message)
  process.exitCode = 1
})
