// 浮层层级集中定义：进度/任务浮层保持在 100 以下，所有组件库弹窗与下拉
// 统一由 Ant Design Vue 管理并高于浮层，避免确认框被安装进度窗口压住。
export const UI_Z_INDEX = {
  modal: 1000,
  confirm: 1100,
  selectDropdown: 1200,
} as const;
