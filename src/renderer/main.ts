import { createApp } from 'vue';
import { ConfigProvider, Drawer, Modal, Select, Switch, Tag } from 'ant-design-vue';
import App from './App.vue';
import './style.css';

// 只注册实际用到的组件；Ant Design Vue 4 采用 CSS-in-JS，无需 reset.css，
// 也不会覆盖本工具已有的设计变量。
createApp(App)
  .use(ConfigProvider)
  .use(Select)
  .use(Switch)
  .use(Modal)
  .use(Drawer)
  .use(Tag)
  .mount('#app');
