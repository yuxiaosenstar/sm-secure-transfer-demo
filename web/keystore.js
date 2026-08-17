/**
 * 会话密钥本地存储(localStorage)。
 *
 * 上传完成后把 SM4 会话密钥 + Merkle 根 + 文件名记入浏览器本地,供日后下载
 * 解密与完整性交叉核对(见 download-manager 的三方核对)。密钥只存本浏览器,
 * 换设备/清除站点数据即无法解密 —— 这是"加密传输"模型下免密体验的取舍。
 */
const KEYSTORE = 'sm-vault-keys'

const keyStore = {
  get(fileId) {
    try { return JSON.parse(localStorage.getItem(KEYSTORE) || '{}')[fileId] || null } catch { return null }
  },
  set(fileId, rec) {
    const all = JSON.parse(localStorage.getItem(KEYSTORE) || '{}')
    all[fileId] = rec
    localStorage.setItem(KEYSTORE, JSON.stringify(all))
  },
  remove(fileId) {
    const all = JSON.parse(localStorage.getItem(KEYSTORE) || '{}')
    delete all[fileId]
    localStorage.setItem(KEYSTORE, JSON.stringify(all))
  },
}

export { KEYSTORE, keyStore }
