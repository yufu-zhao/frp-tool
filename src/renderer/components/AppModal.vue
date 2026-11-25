<script setup lang="ts">
// 统一弹窗骨架：由 Ant Design Vue Modal 负责 Teleport、遮罩、ESC、焦点与滚动锁，
// 本组件只保留原有的标题 / 尺寸 / 说明 / 页脚结构与对外 API。
import { computed } from 'vue';
import { UI_Z_INDEX } from '../ui-z-index';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    description?: string;
    size?: 'sm' | 'md' | 'lg' | 'xl';
    closable?: boolean;
    busy?: boolean;
  }>(),
  { size: 'md', closable: true, busy: false },
);
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'update:open', value: boolean): void;
}>();

const widths = { sm: 440, md: 620, lg: 820, xl: 1000 };
const width = computed(() => widths[props.size]);
function requestClose() {
  if (!props.closable || props.busy) return;
  emit('close');
  emit('update:open', false);
}
</script>

<template>
  <a-modal
    :open="open"
    :width="width"
    :z-index="UI_Z_INDEX.modal"
    :closable="false"
    :mask-closable="closable && !busy"
    :keyboard="closable && !busy"
    :footer="null"
    :body-style="{ padding: 0 }"
    :destroy-on-close="true"
    wrap-class-name="ui-modal-wrap"
    @cancel="requestClose"
  >
    <section
      class="modal"
      :class="`modal--${size}`"
      role="dialog"
      aria-modal="true"
      :aria-label="title"
    >
      <header class="modal__head">
        <div class="modal__titles">
          <h2>{{ title }}</h2>
          <p v-if="description" class="modal__desc">{{ description }}</p>
        </div>
        <slot name="header-extra" />
        <button
          v-if="closable"
          class="modal__close"
          type="button"
          :disabled="busy"
          aria-label="关闭弹窗"
          @click="requestClose"
        >
          ×
        </button>
      </header>
      <div class="modal__body">
        <slot />
      </div>
      <footer v-if="$slots.footer" class="modal__footer">
        <slot name="footer" />
      </footer>
    </section>
  </a-modal>
</template>
