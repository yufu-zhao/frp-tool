<script setup lang="ts">
// 危险 / 重要操作确认。Ant Design Vue Modal 统一负责遮罩、ESC 与焦点管理；
// 风险级别决定配色与默认焦点：危险操作默认聚焦「取消」，且可要求输入确认词。
import { computed, nextTick, ref, watch } from 'vue';
import { UI_Z_INDEX } from '../ui-z-index';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message?: string;
    level?: string;
    impacts?: string[];
    confirmWord?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    // 可选第三动作：用于「保存只读 / 移除重装 / 取消」这类三选场景。
    altLabel?: string;
    altTone?: 'primary' | 'danger' | 'soft';
    busy?: boolean;
  }>(),
  { level: 'normal', confirmLabel: '确认', cancelLabel: '取消', busy: false },
);
const emit = defineEmits<{
  (e: 'confirm'): void;
  (e: 'alt'): void;
  (e: 'cancel'): void;
  (e: 'update:open', value: boolean): void;
}>();

const inputText = ref('');
const cancelBtn = ref<HTMLButtonElement | null>(null);

const canConfirm = computed(
  () => !props.confirmWord || inputText.value.trim() === props.confirmWord.trim(),
);

function close() {
  if (props.busy) return;
  emit('cancel');
  emit('update:open', false);
}
function onConfirm() {
  if (!canConfirm.value || props.busy) return;
  emit('confirm');
}
function onAlt() {
  if (props.busy) return;
  emit('alt');
}
watch(
  () => props.open,
  async (open) => {
    if (!open) return;
    inputText.value = '';
    await nextTick();
    // 危险操作默认停在「取消」，避免误按回车直接确认。
    cancelBtn.value?.focus();
  },
);
</script>

<template>
  <a-modal
    :open="open"
    :z-index="UI_Z_INDEX.confirm"
    :width="470"
    :closable="false"
    :mask-closable="!busy"
    :keyboard="!busy"
    :footer="null"
    :body-style="{ padding: 0 }"
    :destroy-on-close="true"
    wrap-class-name="ui-confirm-wrap"
    @cancel="close"
  >
    <div
      class="confirm"
      :class="`confirm--${level}`"
      role="alertdialog"
      aria-modal="true"
      :aria-label="title"
    >
      <div class="confirm__head">
        <span class="confirm__icon" aria-hidden="true">
          {{ level === 'danger' ? '!' : level === 'warning' ? '!' : '?' }}
        </span>
        <h2>{{ title }}</h2>
      </div>
      <p v-if="message" class="confirm__message">{{ message }}</p>

      <div v-if="impacts && impacts.length" class="confirm__impacts">
        <span class="confirm__impacts-title">此操作将产生以下影响</span>
        <ul>
          <li v-for="(item, index) in impacts" :key="index">{{ item }}</li>
        </ul>
      </div>

      <div v-if="confirmWord" class="confirm__word">
        <label for="confirm-word">
          请输入 <code>{{ confirmWord }}</code> 以确认继续
        </label>
        <input
          id="confirm-word"
          v-model="inputText"
          type="text"
          autocomplete="off"
          spellcheck="false"
          :placeholder="confirmWord"
          @keyup.enter="onConfirm"
        />
      </div>

      <div class="confirm__actions">
        <button ref="cancelBtn" class="ui-btn" type="button" @click="close">
          {{ cancelLabel }}
        </button>
        <button
          v-if="altLabel"
          class="ui-btn"
          :class="altTone ? `ui-btn--${altTone}` : 'ui-btn--soft'"
          type="button"
          :disabled="busy"
          @click="onAlt"
        >
          {{ altLabel }}
        </button>
        <button
          class="ui-btn"
          :class="level === 'danger' ? 'ui-btn--danger' : 'ui-btn--primary'"
          type="button"
          :disabled="!canConfirm || busy"
          @click="onConfirm"
        >
          {{ busy ? '处理中…' : confirmLabel }}
        </button>
      </div>
    </div>
  </a-modal>
</template>
