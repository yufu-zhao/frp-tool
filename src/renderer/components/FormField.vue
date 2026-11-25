<script setup lang="ts">
// 表单字段容器：标签、说明、必填标记与内联校验错误（不再用覆盖式全局错误条）。
import { onMounted, onUpdated, ref, useId } from 'vue';

withDefaults(
  defineProps<{
    label?: string;
    hint?: string;
    error?: string;
    required?: boolean;
    full?: boolean;
  }>(),
  { required: false, full: false },
);

// 插槽里的控件由调用方书写，无法直接写死 for/id；在渲染后把标签与第一个
// 表单控件关联起来，保证点击标签聚焦、读屏与 getByLabel 之类的可访问性查询有效。
const fieldId = useId();
const root = ref<HTMLElement | null>(null);
const labelEl = ref<HTMLLabelElement | null>(null);
function bindControl() {
  const control = root.value?.querySelector<HTMLElement>('input, select, textarea');
  if (!control) return;
  if (!control.id) control.id = fieldId;
  if (labelEl.value) labelEl.value.htmlFor = control.id;
}
onMounted(bindControl);
onUpdated(bindControl);
</script>

<template>
  <div ref="root" class="field" :class="{ 'field--full': full, 'field--invalid': !!error }">
    <label
      v-if="label"
      ref="labelEl"
      class="field__label"
      :class="{ 'field__label--required': required }"
    >
      {{ label }}
    </label>
    <slot />
    <p v-if="error" class="field__error" role="alert">
      <span aria-hidden="true">!</span>{{ error }}
    </p>
    <p v-else-if="hint" class="field__hint">{{ hint }}</p>
  </div>
</template>
