<script setup lang="ts">
// 统一下拉：保留调用处熟悉的 <option> 写法，实际渲染 Ant Design Vue 的 Select。
// 这样原生下拉的键盘体验、浮层层级和主题都由组件库负责，调用方无需逐处改数据结构。
import { computed, useAttrs, useSlots, type VNode } from 'vue';
import { UI_Z_INDEX } from '../ui-z-index';

defineOptions({ inheritAttrs: false });

const props = withDefaults(
  defineProps<{
    modelValue?: string | number | null;
    disabled?: boolean;
    placeholder?: string;
    allowClear?: boolean;
  }>(),
  { modelValue: '', disabled: false, allowClear: false },
);
const emit = defineEmits<{
  (e: 'update:modelValue', value: string | number | null): void;
  (e: 'change', value: string | number | null): void;
}>();
const slots = useSlots();
const attrs = useAttrs();

function flatten(nodes: VNode[]): VNode[] {
  const result: VNode[] = [];
  for (const node of nodes) {
    if (!node || typeof node !== 'object') continue;
    if (node.type === 'option') {
      result.push(node);
      continue;
    }
    if (Array.isArray(node.children)) result.push(...flatten(node.children as VNode[]));
  }
  return result;
}
function labelOf(children: unknown): string {
  if (Array.isArray(children)) return children.map(labelOf).join('');
  if (typeof children === 'string' || typeof children === 'number') return String(children);
  if (children && typeof children === 'object' && 'children' in children)
    return labelOf((children as { children: unknown }).children);
  return '';
}
const options = computed(() =>
  flatten(slots.default?.() ?? []).map((node) => {
    const label = labelOf(node.children);
    const value = node.props?.value ?? label;
    return { label, value, disabled: node.props?.disabled === '' || node.props?.disabled === true };
  }),
);

function onChange(value: unknown) {
  const next = (value ?? '') as string | number | null;
  emit('update:modelValue', next);
  emit('change', next);
}
</script>

<template>
  <a-select
    v-bind="attrs"
    class="app-select"
    :id="attrs.id as string | undefined"
    :value="props.modelValue === '' ? undefined : props.modelValue"
    :options="options"
    :disabled="props.disabled"
    :placeholder="props.placeholder"
    :allow-clear="props.allowClear"
    :dropdown-style="{ zIndex: UI_Z_INDEX.selectDropdown }"
    @update:value="onChange"
  />
</template>
