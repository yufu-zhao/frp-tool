<script setup lang="ts">
// 非阻塞轻量反馈：成功 / 信息 / 警告 / 错误四级，可堆叠、可手动关闭、可带一个动作按钮。
interface ToastItem {
  id: string;
  type: 'success' | 'info' | 'warning' | 'error';
  message: string;
  title?: string;
  actionLabel?: string;
}

defineProps<{ items: ToastItem[] }>();
const emit = defineEmits<{
  (e: 'dismiss', id: string): void;
  (e: 'action', id: string): void;
}>();

const icons: Record<string, string> = { success: '✓', info: 'i', warning: '!', error: '×' };
const titles: Record<string, string> = {
  success: '操作成功',
  info: '提示',
  warning: '请注意',
  error: '操作失败',
};
</script>

<template>
  <Teleport to="body">
    <div class="toast-host" aria-live="polite" aria-atomic="false">
      <TransitionGroup name="toast">
        <div
          v-for="item in items"
          :key="item.id"
          class="toast"
          :class="`toast--${item.type}`"
          role="status"
        >
          <span class="toast__icon" aria-hidden="true">{{ icons[item.type] }}</span>
          <div class="toast__body">
            <strong class="toast__title">{{ item.title || titles[item.type] }}</strong>
            <p class="toast__msg">{{ item.message }}</p>
            <button v-if="item.actionLabel" class="toast__action" @click="emit('action', item.id)">
              {{ item.actionLabel }}
            </button>
          </div>
          <button class="toast__close" aria-label="关闭消息" @click="emit('dismiss', item.id)">
            ×
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>
