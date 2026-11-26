<script setup lang="ts">
// 统一抽屉骨架：由 Ant Design Vue Drawer 负责 Teleport、遮罩、ESC 与滚动锁。
// 对外 API 与 AppModal 保持一致，方便详情页复用同一套页头/页脚写法。
import { UI_Z_INDEX } from '../ui-z-index';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    width?: number;
    closable?: boolean;
    busy?: boolean;
  }>(),
  { width: 520, closable: true, busy: false },
);
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'update:open', value: boolean): void;
}>();
function requestClose() {
  emit('close');
  emit('update:open', false);
}
</script>

<template>
  <a-drawer
    :open="open"
    :width="width"
    :z-index="UI_Z_INDEX.modal"
    :closable="false"
    :mask-closable="closable && !busy"
    :keyboard="closable && !busy"
    :body-style="{ padding: 0 }"
    wrap-class-name="ui-drawer-wrap"
    @close="requestClose"
  >
    <section class="drawer" role="dialog" aria-modal="true" :aria-label="title">
      <header class="drawer__head">
        <h2>{{ title }}</h2>
        <button
          v-if="closable"
          class="modal__close"
          type="button"
          :disabled="busy"
          aria-label="关闭抽屉"
          @click="requestClose"
        >
          ×
        </button>
      </header>
      <div class="drawer__body">
        <slot />
      </div>
      <footer v-if="$slots.footer" class="drawer__footer">
        <slot name="footer" />
      </footer>
    </section>
  </a-drawer>
</template>
