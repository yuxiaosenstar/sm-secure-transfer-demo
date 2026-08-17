/**
 * 应用入口:挂载引导。
 *
 * 组件本体(模板 + 全局样式 + 逻辑)已迁至 web/App.vue(SFC,Options API);
 * 传输编排在 web/secure/ 请求加密库中。本文件只负责把根组件挂到 #app。
 */
import { createApp } from 'vue'
import App from './App.vue'

createApp(App).mount('#app')
