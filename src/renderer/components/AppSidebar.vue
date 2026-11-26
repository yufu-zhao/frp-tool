<script setup lang="ts">
// 扁平主导航：菜单项直接平铺，不做分组折叠；窄窗口可收成图标条。

interface NavItem {
  key: string;
  label: string;
  icon: string;
  badge?: number;
}

withDefaults(
  defineProps<{
    items: NavItem[];
    active: string;
    platform?: string;
    arch?: string;
    secureStorage?: boolean;
    collapsed?: boolean;
    logo?: string;
  }>(),
  {
    platform: '',
    arch: '',
    secureStorage: true,
    collapsed: false,
  },
);
const emit = defineEmits<{
  (e: 'navigate', key: string): void;
  (e: 'quit'): void;
  (e: 'toggle-collapse'): void;
}>();

// 线性图标：24 视窗，1.7 描边，统一 currentColor，跟随明暗主题。
const ICONS: Record<string, string[]> = {
  servers: ['M4 5h16v5H4z', 'M4 14h16v5H4z', 'M7 7.5h.01', 'M7 16.5h.01'],
  versions: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M4 7.5l8 4.5 8-4.5', 'M12 12v9'],
  clients: ['M4 8h11l-2.5-2.5', 'M15 8l-2.5 2.5', 'M20 16H9l2.5 2.5', 'M9 16l2.5-2.5'],
  serverCerts: ['M12 3l7 3v5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z', 'M9 12l2 2 4-4'],
  dns: [
    'M12 3a9 9 0 100 18 9 9 0 000-18z',
    'M3 12h18',
    'M12 3c2.5 2.6 2.5 15.4 0 18',
    'M12 3c-2.5 2.6-2.5 15.4 0 18',
  ],
  terminal: ['M5 7l4 4-4 4', 'M11 17h8'],
  settings: [
    'M12 9a3 3 0 100 6 3 3 0 000-6z',
    'M19.4 13a7 7 0 000-2l2-1.5-2-3.4-2.3 1a7 7 0 00-1.7-1L14.6 3h-4l-.3 2.1a7 7 0 00-1.7 1L6.3 5l-2 3.4 2 1.5a7 7 0 000 2l-2 1.5 2 3.4 2.3-1a7 7 0 001.7 1l.3 2.1h4l.3-2.1a7 7 0 001.7-1l2.3 1 2-3.4z',
  ],
  help: [
    'M12 3a9 9 0 100 18 9 9 0 000-18z',
    'M9.5 9a2.5 2.5 0 114 2c-1 .8-1.5 1.3-1.5 2.5',
    'M12 17h.01',
  ],
};
const iconPaths = (key: string) => ICONS[key] ?? ICONS.servers;
</script>

<template>
  <aside class="sidebar" :class="{ 'sidebar--collapsed': collapsed }" aria-label="主导航">
    <div class="sidebar__brand">
      <div class="sidebar__mark">
        <img v-if="logo" :src="logo" alt="穿透工作台标志" />
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

    <nav class="sidebar__nav" aria-label="功能菜单">
      <button
        v-for="item in items"
        :key="item.key"
        class="nav-item"
        :class="{ 'nav-item--active': active === item.key }"
        type="button"
        :title="collapsed ? item.label : undefined"
        :aria-current="active === item.key ? 'page' : undefined"
        @click="emit('navigate', item.key)"
      >
        <svg class="nav-item__icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            v-for="(d, i) in iconPaths(item.icon)"
            :key="i"
            :d="d"
            stroke="currentColor"
            stroke-width="1.7"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        <span class="nav-item__label">{{ item.label }}</span>
        <b v-if="item.badge !== undefined" class="nav-item__badge">{{ item.badge }}</b>
      </button>
    </nav>

    <div class="sidebar__foot">
      <div class="sidebar__runtime">
        <small>本机 · {{ platform || '连接中' }} / {{ arch || '—' }}</small>
      </div>
      <p v-if="!secureStorage" class="sidebar__warn">安全存储不可用，凭据仅本次会话保留。</p>
      <button class="sidebar__quit" type="button" @click="emit('quit')">退出并停止本机穿透</button>
    </div>
  </aside>
</template>
