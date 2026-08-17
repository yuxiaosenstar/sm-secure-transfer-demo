/**
 * 磁盘存储层。布局:
 *   data/
 *     keypair.json                 服务器 SM2 密钥对(首次启动生成)
 *     uploads/<uuid>/meta.json     上传中会话(每块校验通过后原子持久化)
 *     uploads/<uuid>/chunk-0000000000.enc  密文块 = [IV(16) | 密文]
 *     files/<uuid>/...             已转正文件(同上结构,meta.completed = true)
 *
 * 安全约定:所有 id 均为服务端生成的 uuid,拼接路径前必须过 isValidId;客户端
 * 提供的 name 只作为展示字段存 meta,绝不用于路径。所有写入走 .tmp + rename 原子
 * 化,防止"重试覆盖进行中 vs complete 读取"读到半截文件。
 */
import fs from 'node:fs'
import path from 'node:path'
import { sm2 } from 'sm-crypto'

const DATA_DIR = process.env.SM_DATA_DIR
  ? path.resolve(process.env.SM_DATA_DIR)
  : path.join(import.meta.dirname, '..', 'data')

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true })
}

/**
 * 原子写:.tmp 写入后 rename 到目标。
 * 同一文件的并发读写方(重试覆盖中的块文件 vs complete 的结构检查)绝不会读到
 * 半截内容 —— rename 在 POSIX 上是原子的,读者要么看到旧完整文件,要么看到新完整文件。
 */
function atomicWrite(file, data) {
  ensureDir(path.dirname(file))
  const tmp = `${file}.tmp`
  fs.writeFileSync(tmp, data)
  fs.renameSync(tmp, file)
}

/** 首次启动生成并持久化 SM2 密钥对;已存在则加载 */
function ensureKeypair() {
  const file = path.join(DATA_DIR, 'keypair.json')
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'))
  const { publicKey, privateKey } = sm2.generateKeyPairHex()
  const kp = { publicKey, privateKey, createdAt: Date.now() }
  atomicWrite(file, JSON.stringify(kp, null, 2))
  return kp
}

function isValidId(id) {
  return typeof id === 'string' && UUID_RE.test(id)
}

function scopeDir(scope) {
  const dir = path.join(DATA_DIR, scope)
  ensureDir(dir)
  return dir
}

function itemDir(scope, id) {
  return path.join(scopeDir(scope), id)
}

/** 块文件名固定 10 位零填充:字典序 == 数字序,任何按文件名的排序/范围操作都等价于按索引 */
function chunkFileName(index) {
  return `chunk-${String(index).padStart(10, '0')}.enc`
}

/** 第 index 块的明文长度(末块可能不足 chunkSize) */
function plainLenOf(meta, index) {
  return Math.min(meta.chunkSize, meta.size - index * meta.chunkSize)
}

function initItem(scope, id, meta) {
  const dir = itemDir(scope, id)
  ensureDir(dir)
  writeMeta(scope, id, meta)
}

function writeMeta(scope, id, meta) {
  atomicWrite(path.join(itemDir(scope, id), 'meta.json'), JSON.stringify(meta))
}

function readMeta(scope, id) {
  try {
    return JSON.parse(fs.readFileSync(path.join(itemDir(scope, id), 'meta.json'), 'utf8'))
  } catch {
    return null
  }
}

function writeChunkFile(scope, id, index, buf) {
  atomicWrite(path.join(itemDir(scope, id), chunkFileName(index)), buf)
}

function readChunkFile(scope, id, index) {
  try {
    return fs.readFileSync(path.join(itemDir(scope, id), chunkFileName(index)))
  } catch {
    return null
  }
}

function chunkExists(scope, id, index) {
  return fs.existsSync(path.join(itemDir(scope, id), chunkFileName(index)))
}

function listItems(scope) {
  return fs.readdirSync(scopeDir(scope)).filter(isValidId)
}

function removeItem(scope, id) {
  fs.rmSync(itemDir(scope, id), { recursive: true, force: true })
}

/** 上传转正:uploads/<id> 原子移到 files/<id> */
function moveItem(fromScope, id, toScope) {
  const from = itemDir(fromScope, id)
  const to = itemDir(toScope, id)
  ensureDir(scopeDir(toScope))
  fs.rmSync(to, { recursive: true, force: true }) // 目标残留则先清
  fs.renameSync(from, to)
}

export {
  DATA_DIR,
  ensureKeypair,
  isValidId,
  plainLenOf,
  initItem,
  writeMeta,
  readMeta,
  writeChunkFile,
  readChunkFile,
  chunkExists,
  listItems,
  removeItem,
  moveItem,
}
