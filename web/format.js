/**
 * 展示格式化工具(纯函数,无状态)。
 *
 * 独立成模块的原因:formatBytes/formatTime/shortHex 被 Vue 模板(挂组件)使用,
 * 而 formatSpeed/formatTimeShort 被 UploadManager 的速度采样使用 —— 若留在
 * main.js 会造成 main.js ↔ upload-manager 循环 import。
 */

export function formatBytes(n) {
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

export function formatSpeed(bytesPerSec) {
  return formatBytes(bytesPerSec) + '/s'
}

export function formatTime(ts) {
  const d = new Date(ts)
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export function formatTimeShort(seconds) {
  if (!isFinite(seconds) || seconds < 0) return ''
  const s = Math.round(seconds)
  if (s < 60) return s + 's'
  if (s < 3600) return Math.floor(s / 60) + 'm' + (s % 60) + 's'
  return Math.floor(s / 3600) + 'h' + Math.floor((s % 3600) / 60) + 'm'
}

export function shortHex(hex, n = 8) {
  return hex ? hex.slice(0, n) + '…' + hex.slice(-4) : '—'
}
