<script setup lang="ts">
// 空状态占位，统一各页面的“还没有数据”引导。
withDefaults(
  defineProps<{
    icon?: string;
    title: string;
    description?: string;
    compact?: boolean;
  }>(),
  { icon: '◇', compact: false },
);
</script>

<template>
  <div class="empty" :class="{ 'empty--compact': compact }">
    <div class="empty__icon" aria-hidden="true">{{ icon }}</div>
    <h3>{{ title }}</h3>
    <p v-if="description">{{ description }}</p>
    <div v-if="$slots.action" class="empty__action">
      <slot name="action" />
    </div>
    <slot />
  </div>
</template>
