<script setup lang="ts">
// 统一状态徽标：服务器 / 服务 / 实例 / 证书状态机 / 下载状态 / 托管实例共用。
withDefaults(
  defineProps<{
    tone?: string;
    label?: string;
    dot?: boolean;
  }>(),
  { tone: 'neutral', dot: true },
);
</script>

<template>
  <a-tag class="badge ui-badge" :class="`badge--${tone}`" :bordered="false" :title="label">
    <span v-if="dot" class="badge__dot" aria-hidden="true"></span>
    <slot>{{ label }}</slot>
  </a-tag>
</template>
