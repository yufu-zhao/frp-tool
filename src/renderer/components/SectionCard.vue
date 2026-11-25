<script setup lang="ts">
// 区块卡片：标题 + 描述 + 右上操作区 + 内容 + 可选页脚。
withDefaults(
  defineProps<{
    title?: string;
    description?: string;
    tone?: 'default' | 'muted' | 'warning';
    flush?: boolean;
  }>(),
  { tone: 'default', flush: false },
);
</script>

<template>
  <section class="card" :class="[`card--${tone}`, { 'card--flush': flush }]">
    <div v-if="title || $slots.actions" class="card__head">
      <div>
        <h2 v-if="title" class="card__title">{{ title }}</h2>
        <p v-if="description" class="card__desc">{{ description }}</p>
      </div>
      <div v-if="$slots.actions" class="card__actions">
        <slot name="actions" />
      </div>
    </div>
    <div class="card__body">
      <slot />
    </div>
    <div v-if="$slots.footer" class="card__footer">
      <slot name="footer" />
    </div>
  </section>
</template>
