<script setup lang="ts">
// 工作流分组侧栏：分组标题、可折叠、活动态、计数徽标、运行状态指示；可 fold 成图标条。
import { reactive } from 'vue';

interface NavItem {
  key: string;
  label: string;
  icon: string;
  badge?: number;
}
interface NavGroup {
  key: string;
  label: string;
  items: NavItem[];
}

const props = withDefaults(
  defineProps<{
    groups: NavGroup[];
    active: string;
    platform?: string;
    arch?: string;
    secureStorage?: boolean;
    runtimeLabel?: string;
    runtimeTone?: string;
    collapsed?: boolean;
    logo?: string;
  }>(),
  {
    platform: '',
    arch: '',
    secureStorage: true,
    runtimeLabel: '就绪',
    runtimeTone: 'success',
    collapsed: false,
  },
);
const emit = defineEmits<{
  (e: 'navigate', key: string): void;
  (e: 'quit'): void;
  (e: 'toggle-collapse'): void;
}>();

const openGroups = reactive<Record<string, boolean>>({});
function isOpen(key: string) {
  return openGroups[key] !== false;
}
function toggleGroup(key: string) {
  openGroups[key] = !isOpen(key);
}
function onNavigate(key: string) {
  emit('navigate', key);
}
</script>

<template>
  <aside class="sidebar" :class="{ 'sidebar--collapsed': collapsed }" aria-label="主导航">
    <div class="sidebar__brand">
      <div class="sidebar__mark">
        <img v-if="logo" :src="logo" alt="穿透工作台标志" />
        <span v-else aria-hidden="true">⇄</span>
      </div>
      <div class="sidebar__brand-text">
        <strong>穿透工作台</strong>
        <small>INTRANET / FRP</small>
      </div>
      <button
        class="sidebar__fold"
        type="button"
        :aria-label="collapsed ? '展开侧栏' : '收起侧栏'"
        @click="emit('toggle-collapse')"
      >
        {{ collapsed ? '»' : '«' }}
      </button>
    </div>

    <div class="sidebar__scroll">
      <div v-for="group in groups" :key="group.key" class="nav-group">
        <button class="nav-group__head" type="button" @click="toggleGroup(group.key)">
          <span class="nav-group__label">{{ group.label }}</span>
          <span class="nav-group__chevron" aria-hidden="true">{{
            isOpen(group.key) ? '−' : '+'
          }}</span>
        </button>
        <div v-show="isOpen(group.key)" class="nav-group__items">
          <button
            v-for="item in group.items"
            :key="item.key"
            class="nav-item"
            :class="{ 'nav-item--active': active === item.key }"
            type="button"
            :title="item.label"
            @click="onNavigate(item.key)"
          >
            <span class="nav-item__icon" aria-hidden="true">{{ item.icon }}</span>
            <span class="nav-item__label">{{ item.label }}</span>
            <b v-if="item.badge !== undefined" class="nav-item__badge">{{ item.badge }}</b>
          </button>
        </div>
      </div>
    </div>

    <div class="sidebar__foot">
      <div class="sidebar__runtime">
        <span class="badge" :class="`badge--${runtimeTone}`">
          <span class="badge__dot" aria-hidden="true"></span>{{ runtimeLabel }}
        </span>
        <small>本机 · {{ platform || '连接中' }} / {{ arch || '—' }}</small>
      </div>
      <p v-if="!secureStorage" class="sidebar__warn">系统安全存储不可用，凭据仅本次会话保留。</p>
      <button class="sidebar__quit" type="button" @click="emit('quit')">退出并停止本机穿透</button>
    </div>
  </aside>
</template>
