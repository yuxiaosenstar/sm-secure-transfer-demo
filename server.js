/**
 * SM 加密传输服务端。演示项目,单文件应用。
 *
 * 模型:客户端 SM4 分块加密上传(SM2 封装会话密钥),服务器临时解密做 SM3 完整性
 * 校验,但只落盘密文 —— 明文永不落盘;下载直接下发密文块,传输通道上即为密文。
 *
 * 启动:npm run dev(开发,内嵌 Vite middleware 单进程)或 npm start(生产,服务 dist/)。
 * 默认端口 3900,SM_DATA_DIR 可指定数据目录;导出 createApp() 供测试进程内启动。
 */
import express from 'express'
import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import * as shared from './web/shared/crypto.js'
import * as store from './src/store.js'
import * as sessions from './src/sessions.js'
import * as native from './src/crypto-native.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isProd = process.env.NODE_ENV === 'production'

const MIN_CHUNK_SIZE = 1024 * 1024 // 1 MiB
const MAX_CHUNK_SIZE = 16 * 1024 * 1024 // 16 MiB(express.raw limit 需覆盖)
const MAX_SIZE = 100 * 1024 * 1024 * 1024 // 100 GiB
const MAX_CHUNK_COUNT = 100000
const RAW_LIMIT = '18mb' // 16MiB 块 + IV + 填充 + 余量

function sanitizeName(name) {
  const s = String(name ?? '').replace(/[\/\\\0]/g, '').trim()
  return (s || 'unnamed').slice(0, 255)
}

function bad(res, status, message) {
  return res.status(status).json({ error: message })
}

function createApp() {
  const app = express()
  app.use(express.json({ limit: '1mb' }))

  // API 响应不缓存
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store')
    next()
  })

  const keypair = store.ensureKeypair()

  // 启动时清理超过 24 小时的未完成上传会话(防僵尸目录堆积)
  for (const id of store.listItems('uploads')) {
    const meta = store.readMeta('uploads', id)
    if (meta && Date.now() - meta.createdAt > 24 * 3600 * 1000) store.removeItem('uploads', id)
  }

  // ---- 密钥 ----
  app.get('/api/pubkey', (req, res) => {
    res.json({
      publicKey: keypair.publicKey,
      fingerprint: native.sm3Hex(Buffer.from(keypair.publicKey, 'hex')).slice(0, 16),
    })
  })

  // ---- 上传初始化:校验元数据,解封 SM4 会话密钥 ----
  app.post('/api/upload/init', (req, res) => {
    const { name, size, chunkSize, wrappedKey } = req.body ?? {}
    if (!Number.isInteger(size) || size < 0 || size > MAX_SIZE) {
      return bad(res, 400, 'size 非法')
    }
    if (!Number.isInteger(chunkSize) || chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
      return bad(res, 400, `chunkSize 须在 [${MIN_CHUNK_SIZE}, ${MAX_CHUNK_SIZE}]`)
    }
    let keyHex
    try {
      keyHex = sessions.unwrapKey(String(wrappedKey ?? ''))
    } catch (e) {
      return bad(res, 400, e.message)
    }
    const chunkCount = size === 0 ? 0 : Math.ceil(size / chunkSize)
    if (chunkCount > MAX_CHUNK_COUNT) return bad(res, 400, 'chunk 数量超限')

    const id = crypto.randomUUID()
    const meta = {
      id,
      name: sanitizeName(name),
      size,
      chunkSize,
      chunkCount,
      wrappedKey: String(wrappedKey),
      perChunkHash: {},
      rootHash: null,
      completed: false,
      createdAt: Date.now(),
    }
    store.initItem('uploads', id, meta)
    sessions.openSession(id, String(wrappedKey))
    res.status(201).json({ id, chunkCount, keyFingerprint: native.sm3Hex(Buffer.from(keyHex, 'hex')).slice(0, 8) })
  })

  // ---- 分块上传:body = [IV(16) | SM4 密文],头 X-Chunk-Hash = SM3(明文) ----
  app.post(
    '/api/upload/chunk/:id/:index',
    express.raw({ type: 'application/octet-stream', limit: RAW_LIMIT }),
    (req, res) => {
      const { id, index: indexStr } = req.params
      if (!store.isValidId(id)) return bad(res, 404, '会话不存在')
      const index = Number(indexStr)
      if (!Number.isInteger(index) || index < 0) return bad(res, 400, 'index 非法')
      const meta = store.readMeta('uploads', id)
      if (!meta) return bad(res, 404, '会话不存在')
      if (index >= meta.chunkCount) return bad(res, 400, 'index 越界')

      const hash = String(req.get('x-chunk-hash') ?? '').toLowerCase()
      if (!/^[0-9a-f]{64}$/.test(hash)) return bad(res, 400, 'x-chunk-hash 格式非法')

      const body = req.body ?? Buffer.alloc(0)
      const plainLen = store.plainLenOf(meta, index)
      const expectLen = shared.cipherLenOf(plainLen)
      if (body.length !== expectLen) {
        return bad(res, 400, `块 ${index} 长度不符:期望 ${expectLen},实际 ${body.length}`)
      }

      const keyHex = sessions.getSession(id, meta)
      if (!keyHex) return bad(res, 500, '会话密钥不可用')
      const ivHex = body.subarray(0, 16).toString('hex')

      let plain
      try {
        plain = native.sm4Decrypt(keyHex, ivHex, body.subarray(16))
      } catch {
        return bad(res, 422, `块 ${index} 解密失败`)
      }
      if (native.sm3Hex(plain) !== hash) {
        return bad(res, 422, `块 ${index} SM3 完整性校验失败`)
      }

      store.writeChunkFile('uploads', id, index, body)
      meta.perChunkHash[index] = hash
      store.writeMeta('uploads', id, meta) // 每块持久化,重启后断点续传仍成立
      res.status(204).end()
    }
  )

  // ---- 上传状态(断点续传对账):只认"哈希已记录且文件已落盘"的块 ----
  app.get('/api/upload/status/:id', (req, res) => {
    const { id } = req.params
    if (!store.isValidId(id)) return bad(res, 404, '会话不存在')
    const meta = store.readMeta('uploads', id)
    if (!meta) return bad(res, 404, '会话不存在')
    const uploaded = []
    for (let i = 0; i < meta.chunkCount; i++) {
      if (meta.perChunkHash[i] && store.chunkExists('uploads', id, i)) uploaded.push(i)
    }
    res.json({ uploaded, chunkCount: meta.chunkCount, completed: meta.completed })
  })

  // ---- 上传完成:结构性检查 + Merkle 根比对,然后转正 ----
  app.post('/api/upload/complete', (req, res) => {
    const { id, rootHash } = req.body ?? {}
    if (!store.isValidId(id)) return bad(res, 404, '会话不存在')
    const meta = store.readMeta('uploads', id)
    if (!meta) return bad(res, 404, '会话不存在')
    if (meta.completed) return bad(res, 409, '该上传已转正')

    const missing = []
    for (let i = 0; i < meta.chunkCount; i++) {
      if (!meta.perChunkHash[i] || !store.chunkExists('uploads', id, i)) missing.push(i)
    }
    if (missing.length) return bad(res, 400, `存在未上传的块:${missing.slice(0, 20).join(',')}`)

    // 每块密文长度结构校验
    for (let i = 0; i < meta.chunkCount; i++) {
      const buf = store.readChunkFile('uploads', id, i)
      if (!buf || buf.length !== shared.cipherLenOf(store.plainLenOf(meta, i))) {
        return bad(res, 400, `块 ${i} 长度异常`)
      }
    }

    const ordered = []
    for (let i = 0; i < meta.chunkCount; i++) ordered.push(meta.perChunkHash[i])
    const serverRoot = shared.merkleRoot(ordered)
    if (serverRoot !== String(rootHash ?? '').toLowerCase()) {
      return bad(res, 409, '文件级完整性校验失败(Merkle 根不一致)')
    }

    meta.rootHash = serverRoot
    meta.completed = true
    meta.completedAt = Date.now()
    store.writeMeta('uploads', id, meta)
    store.moveItem('uploads', id, 'files')
    sessions.closeSession(id)
    res.json({ fileId: id, rootHash: serverRoot })
  })

  // ---- 文件列表 ----
  app.get('/api/files', (req, res) => {
    const files = store
      .listItems('files')
      .map((id) => {
        const m = store.readMeta('files', id)
        return m && m.completed
          ? {
              id: m.id,
              name: m.name,
              size: m.size,
              chunkSize: m.chunkSize,
              chunkCount: m.chunkCount,
              rootHash: m.rootHash,
              createdAt: m.createdAt,
              completedAt: m.completedAt,
            }
          : null
      })
      .filter(Boolean)
      .sort((a, b) => b.createdAt - a.createdAt)
    res.json({ files })
  })

  // ---- 文件详情(下载初始化:客户端校验参考值来源) ----
  app.get('/api/files/:id', (req, res) => {
    const { id } = req.params
    if (!store.isValidId(id)) return bad(res, 404, '文件不存在')
    const meta = store.readMeta('files', id)
    if (!meta || !meta.completed) return bad(res, 404, '文件不存在')
    const chunkHashes = []
    for (let i = 0; i < meta.chunkCount; i++) chunkHashes.push(meta.perChunkHash[i])
    res.json({
      id: meta.id,
      name: meta.name,
      size: meta.size,
      chunkSize: meta.chunkSize,
      chunkCount: meta.chunkCount,
      rootHash: meta.rootHash,
      chunkHashes,
      wrappedKey: meta.wrappedKey,
      createdAt: meta.createdAt,
    })
  })

  // ---- 下载密文块(completed 门禁) ----
  app.get('/api/download/:id/chunk/:index', (req, res) => {
    const { id, index: indexStr } = req.params
    if (!store.isValidId(id)) return bad(res, 404, '文件不存在')
    const meta = store.readMeta('files', id)
    if (!meta || !meta.completed) return bad(res, 404, '文件不存在')
    const index = Number(indexStr)
    if (!Number.isInteger(index) || index < 0 || index >= meta.chunkCount) {
      return bad(res, 400, 'index 越界')
    }
    const buf = store.readChunkFile('files', id, index)
    if (!buf) return bad(res, 404, '块不存在')
    res.set('Content-Type', 'application/octet-stream')
    res.send(buf)
  })

  // ---- 删除 ----
  app.delete('/api/files/:id', (req, res) => {
    const { id } = req.params
    if (!store.isValidId(id) || !store.readMeta('files', id)) return bad(res, 404, '文件不存在')
    store.removeItem('files', id)
    res.status(204).end()
  })

  // ---- 静态资源(挂在 API 路由之后:未知 /api 请求须穿过 Vite 到兜底 404) ----
  // 生产:服务 dist/ 构建产物;开发:内嵌 Vite middleware(单进程 + HMR)
  if (isProd) {
    app.use(express.static(path.join(__dirname, 'dist')))
  } else {
    // Vite middleware 惰性初始化:仅当有非 /api 页面请求时才创建(测试只打 /api 不触发)。
    // /api 一律跳过 —— appType 'spa' 的 HTML fallback 会吞掉任何未命中路径,必须放行未知 /api。
    let vitePromise = null
    app.use(async (req, res, next) => {
      if (req.path.startsWith('/api')) return next()
      try {
        if (!vitePromise) {
          const { createServer } = await import('vite')
          vitePromise = createServer({
            root: __dirname,
            server: { middlewareMode: true },
            appType: 'spa',
          })
        }
        const vite = await vitePromise
        return vite.middlewares(req, res, next)
      } catch (err) {
        return next(err)
      }
    })
  }

  // ---- 兜底 ----
  app.use('/api', (req, res) => bad(res, 404, '接口不存在'))
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('未处理异常:', err)
    bad(res, 500, '服务器内部错误')
  })

  return app
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT) || 3900
  createApp().listen(port, () => {
    console.log(`SM 加密传输服务已启动: http://localhost:${port}(${isProd ? '生产,服务 dist/' : '开发,Vite middleware'})`)
    console.log(`数据目录: ${store.DATA_DIR}`)
    console.log(`服务端 SM3/SM4 快路径: ${native.HAS_NATIVE ? 'Node 原生 crypto' : 'sm-crypto 纯 JS'}`)
  })
}

export { createApp }
