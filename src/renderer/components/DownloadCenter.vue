<script setup lang="ts">
// 应用内常驻的下载任务中心：Teleport 到 body 固定右下角，切页面不丢进度，可收起/展开。
import { computed, ref, watch } from 'vue';
import type { DownloadProgress, DownloadTaskView } from '../../shared/types';

// raised：安装进度浮层同时在右下角时，任务中心上移让位，两者不互相遮挡。
const props = defineProps<{ tasks: DownloadTaskView[]; raised?: boolean }>();
const emit = defineEmits<{
  (e: 'cancel', taskId: string): void;
  (e: 'retry', taskId: string): void;
  (e: 'dismiss', taskId: string): void;
  (e: 'clearFinished'): void;
  (e: 'openChange', expanded: boolean): void;
}>();

// 进行中的状态：用于活跃计数、自动展开与「取消」按钮。
const activeStates: DownloadProgress['status'][] = [
  'starting',
  'downloading',
  'retrying',
  'verifying',
  'extracting',
];
const statusLabels: Record<DownloadProgress['status'], string> = {
  starting: '准备中',
  downloading: '下载中',
  retrying: '重试中',
  paused: '已暂停',
  verifying: '校验中',
  extracting: '解压中',
  succeeded: '已完成',
  failed: '失败',
  cancelled: '已取消',
};

const expanded = ref(false);
// 已见过的 taskId 集合：只在出现「新的」活跃任务时自动展开，进度更新不会反复弹开。
const knownIds = ref<Set<string>>(new Set());
const stepOpen = ref<Record<string, boolean>>({});

function setExpanded(value: boolean) {
  if (expanded.value === value) return;
  expanded.value = value;
  emit('openChange', value);
}

// 只比较 taskId 集合；用户手动收起后，只要没有新 taskId 就不会再次自动展开。
watch(
  () => props.tasks.map((t) => t.taskId).join('|'),
  () => {
    const list = props.tasks;
    if (!list.length) {
      knownIds.value = new Set();
      return;
    }
    const hasNewActive = list.some(
      (t) => !knownIds.value.has(t.taskId) && activeStates.includes(t.status),
    );
    knownIds.value = new Set(list.map((t) => t.taskId));
    if (hasNewActive) setExpanded(true);
  },
  { immediate: true },
);

const activeTasks = computed(() => props.tasks.filter((t) => activeStates.includes(t.status)));
const activeCount = computed(() => activeTasks.value.length);
// 主任务：最近更新的活跃任务；无活跃任务时退回到最近更新的任意任务。
const primary = computed(() => {
  const pool = activeTasks.value.length ? activeTasks.value : props.tasks;
  return pool.length ? pool.reduce((best, t) => (t.updatedAt > best.updatedAt ? t : best)) : null;
});
const primaryPercent = computed(() => clampPercent(primary.value?.percent));
const pillLabel = computed(() =>
  activeCount.value ? `${activeCount.value} 个任务进行中` : `${props.tasks.length} 个任务`,
);
const pillAriaLabel = computed(
  () => `展开下载任务中心，${activeCount.value} 个任务进行中，当前进度 ${primaryPercent.value}%`,
);

type Tone = 'primary' | 'success' | 'danger' | 'warning';
function toneOf(status: DownloadProgress['status']): Tone {
  if (status === 'succeeded') return 'success';
  if (status === 'failed' || status === 'cancelled') return 'danger';
  if (status === 'paused') return 'warning';
  return 'primary';
}
function isActive(status: DownloadProgress['status']) {
  return activeStates.includes(status);
}
function canRetry(status: DownloadProgress['status']) {
  return status === 'failed' || status === 'paused';
}
function canDismiss(status: DownloadProgress['status']) {
  return status === 'succeeded' || status === 'failed' || status === 'cancelled';
}
function clampPercent(p?: number | null) {
  return Math.max(0, Math.min(100, Math.round(p ?? 0)));
}
function fmtBytes(n?: number | null) {
  if (n == null || !Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function fmtSpeed(n?: number | null) {
  if (n == null || !Number.isFinite(n) || n <= 0) return '';
  return `${fmtBytes(n)}/s`;
}
function fmtTime(t?: number) {
  if (!t) return '';
  return new Date(t).toLocaleTimeString('zh-CN', { hour12: false });
}
function toggleSteps(taskId: string) {
  stepOpen.value = { ...stepOpen.value, [taskId]: !stepOpen.value[taskId] };
}
</script>

<template>
  <Teleport to="body">
    <div v-if="tasks.length" class="dc-root" :class="{ 'dc-root--raised': raised }">
      <!-- 收起态：小胶囊，显示活跃任务数、主任务百分比、细进度条与展开箭头 -->
      <div v-if="!expanded" class="dc-pill">
        <button
          class="dc-pill__main"
          type="button"
          :aria-label="pillAriaLabel"
          @click="setExpanded(true)"
        >
          <span class="dc-pill__dot" aria-hidden="true"></span>
          <span class="dc-pill__label">{{ pillLabel }}</span>
          <span class="dc-pill__percent">{{ primaryPercent }}%</span>
          <span class="dc-pill__chevron" aria-hidden="true">⌃</span>
        </button>
        <div
          class="dc-pill__track"
          role="progressbar"
          :aria-valuenow="primaryPercent"
          aria-valuemin="0"
          aria-valuemax="100"
          aria-label="主任务下载进度"
        >
          <div class="dc-pill__bar" :style="{ width: `${primaryPercent}%` }"></div>
        </div>
      </div>

      <!-- 展开态：任务卡片列表 -->
      <div v-else class="dc-card">
        <div class="dc-card__head">
          <strong class="dc-card__title">下载任务</strong>
          <span class="dc-card__count">{{ tasks.length }}</span>
          <span class="dc-card__spacer"></span>
          <button
            class="dc-link"
            type="button"
            aria-label="清除已完成的任务"
            @click="emit('clearFinished')"
          >
            清除已完成
          </button>
          <button
            class="dc-icon"
            type="button"
            aria-label="收起下载任务中心"
            @click="setExpanded(false)"
          >
            ⌄
          </button>
        </div>

        <div class="dc-card__list">
          <div
            v-for="task in tasks"
            :key="task.taskId"
            class="dc-task"
            :class="`dc-task--${toneOf(task.status)}`"
          >
            <div class="dc-task__head">
              <span class="dc-badge">{{ statusLabels[task.status] }}</span>
              <span class="dc-task__title" :title="task.label">{{ task.label }}</span>
            </div>

            <div
              class="dc-task__track"
              role="progressbar"
              :aria-valuenow="clampPercent(task.percent)"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-label="`${task.label} 下载进度`"
            >
              <div class="dc-task__bar" :style="{ width: `${clampPercent(task.percent)}%` }"></div>
            </div>

            <div class="dc-task__stats">
              <span class="dc-task__percent">{{ clampPercent(task.percent) }}%</span>
              <span v-if="task.total"
                >{{ fmtBytes(task.received) }} / {{ fmtBytes(task.total) }}</span
              >
              <span v-if="task.speed">{{ fmtSpeed(task.speed) }}</span>
            </div>

            <p v-if="task.message" class="dc-task__message">{{ task.message }}</p>

            <div v-if="task.attempt > 1 || task.resumable" class="dc-task__tags">
              <span v-if="task.attempt > 1" class="dc-tag">第 {{ task.attempt }} 次尝试</span>
              <span v-if="task.resumable" class="dc-tag dc-tag--info">支持断点续传</span>
            </div>

            <!-- 步骤时间线：默认折叠，点击展开 -->
            <div v-if="task.steps && task.steps.length" class="dc-steps">
              <button
                class="dc-steps__toggle"
                type="button"
                :aria-expanded="!!stepOpen[task.taskId]"
                :aria-label="`${stepOpen[task.taskId] ? '收起' : '展开'}步骤详情，共 ${task.steps.length} 步`"
                @click="toggleSteps(task.taskId)"
              >
                <span class="dc-steps__chevron" aria-hidden="true">{{
                  stepOpen[task.taskId] ? '▾' : '▸'
                }}</span>
                步骤详情（{{ task.steps.length }}）
              </button>
              <ol v-if="stepOpen[task.taskId]" class="dc-steps__list">
                <li
                  v-for="(step, index) in task.steps"
                  :key="index"
                  class="dc-steps__item"
                  :class="step.tone ? `is-${step.tone}` : ''"
                >
                  <span class="dc-steps__dot" aria-hidden="true"></span>
                  <div class="dc-steps__text">
                    <strong>{{ step.label }}</strong>
                    <small v-if="step.detail">{{ step.detail }}</small>
                  </div>
                  <time v-if="step.time">{{ fmtTime(step.time) }}</time>
                </li>
              </ol>
            </div>

            <div class="dc-task__actions">
              <button
                v-if="isActive(task.status)"
                class="dc-btn"
                type="button"
                aria-label="取消该下载任务"
                @click="emit('cancel', task.taskId)"
              >
                取消
              </button>
              <button
                v-if="canRetry(task.status)"
                class="dc-btn dc-btn--primary"
                type="button"
                aria-label="重试该下载任务"
                @click="emit('retry', task.taskId)"
              >
                重试
              </button>
              <button
                v-if="canDismiss(task.status)"
                class="dc-btn"
                type="button"
                aria-label="关闭该下载任务"
                @click="emit('dismiss', task.taskId)"
              >
                关闭
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.dc-root {
  position: fixed;
  right: var(--sp-5);
  bottom: var(--sp-5);
  transition: bottom 0.2s ease;
  /* 低于弹窗(100)/确认框(110)：弹窗打开时不遮挡保存与确认按钮；关闭弹窗后仍常驻可见。 */
  z-index: 95;
  width: min(360px, calc(100vw - 32px));
  font-family: var(--font);
  color: var(--c-text);
  font-size: var(--fs-sm);
}
/* 安装进度浮层同样贴右下角时，任务中心上移，避免两个面板叠在一起。 */
.dc-root--raised {
  bottom: calc(var(--sp-5) + 420px);
}

/* ---------- 收起态胶囊 ---------- */
.dc-pill {
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--r-full);
  box-shadow: var(--sh-3);
  overflow: hidden;
}
.dc-pill__main {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  width: 100%;
  border: 0;
  background: transparent;
  color: var(--c-text);
  padding: var(--sp-3) var(--sp-4);
  font-size: var(--fs-sm);
  line-height: 1.4;
  border-radius: 0;
}
.dc-pill__main:hover:not(:disabled) {
  background: var(--c-surface-2);
  border-color: transparent;
  color: var(--c-text);
}
.dc-pill__dot {
  width: 8px;
  height: 8px;
  border-radius: var(--r-full);
  background: var(--c-primary);
  flex: 0 0 auto;
}
.dc-pill__label {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: left;
}
.dc-pill__percent {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--c-primary);
  flex: 0 0 auto;
}
.dc-pill__chevron {
  color: var(--c-text-3);
  font-size: var(--fs-base);
  flex: 0 0 auto;
}
.dc-pill__track {
  height: 3px;
  background: var(--c-surface-2);
}
.dc-pill__bar {
  height: 100%;
  background: var(--c-primary);
  transition: width 0.25s ease;
}

/* ---------- 展开态卡片 ---------- */
.dc-card {
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--r-md);
  box-shadow: var(--sh-3);
  overflow: hidden;
}
.dc-card__head {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  padding: var(--sp-3) var(--sp-4);
  border-bottom: 1px solid var(--c-border);
  background: var(--c-surface-2);
}
.dc-card__title {
  font-size: var(--fs-base);
  color: var(--c-text);
}
.dc-card__count {
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  color: var(--c-primary);
  background: var(--c-primary-soft);
  border-radius: var(--r-full);
  padding: 1px var(--sp-2);
  flex: 0 0 auto;
}
.dc-card__spacer {
  flex: 1;
}
.dc-link {
  border: 0;
  background: transparent;
  color: var(--c-text-3);
  font-size: var(--fs-xs);
  padding: var(--sp-1) var(--sp-2);
  white-space: nowrap;
}
.dc-link:hover:not(:disabled) {
  background: transparent;
  border-color: transparent;
  color: var(--c-primary);
}
.dc-icon {
  border: 0;
  background: transparent;
  color: var(--c-text-3);
  font-size: var(--fs-lg);
  line-height: 1;
  padding: var(--sp-1) var(--sp-2);
  flex: 0 0 auto;
}
.dc-icon:hover:not(:disabled) {
  background: var(--c-surface);
  border-color: transparent;
  color: var(--c-text);
}
.dc-card__list {
  max-height: min(60vh, 520px);
  overflow-y: auto;
}

/* ---------- 单个任务：状态色由 --dc-tone 派生 ---------- */
.dc-task {
  --dc-tone: var(--c-primary);
  --dc-tone-soft: var(--c-primary-soft);
  padding: var(--sp-3) var(--sp-4);
  border-bottom: 1px solid var(--c-border);
}
.dc-task:last-child {
  border-bottom: 0;
}
.dc-task--success {
  --dc-tone: var(--c-success);
  --dc-tone-soft: var(--c-success-soft);
}
.dc-task--danger {
  --dc-tone: var(--c-danger);
  --dc-tone-soft: var(--c-danger-soft);
}
.dc-task--warning {
  --dc-tone: var(--c-warning);
  --dc-tone-soft: var(--c-warning-soft);
}
.dc-task__head {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  min-width: 0;
}
.dc-badge {
  flex: 0 0 auto;
  font-size: var(--fs-xs);
  line-height: 1.4;
  border-radius: var(--r-sm);
  padding: 2px var(--sp-2);
  color: var(--dc-tone);
  background: var(--dc-tone-soft);
  white-space: nowrap;
}
.dc-task__title {
  font-size: var(--fs-sm);
  color: var(--c-text);
  font-weight: 600;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dc-task__track {
  height: 6px;
  border-radius: var(--r-full);
  background: var(--c-surface-2);
  overflow: hidden;
  margin-top: var(--sp-2);
}
.dc-task__bar {
  height: 100%;
  border-radius: var(--r-full);
  background: var(--dc-tone);
  transition: width 0.25s ease;
}
.dc-task__stats {
  display: flex;
  justify-content: space-between;
  gap: var(--sp-2);
  margin-top: var(--sp-1);
  font-size: var(--fs-xs);
  color: var(--c-text-3);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  flex-wrap: wrap;
}
.dc-task__percent {
  color: var(--c-text);
  font-weight: 700;
}
.dc-task__message {
  margin-top: var(--sp-2);
  font-size: var(--fs-xs);
  color: var(--c-text-2);
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.dc-task__tags {
  display: flex;
  gap: var(--sp-2);
  flex-wrap: wrap;
  margin-top: var(--sp-2);
}
.dc-tag {
  font-size: var(--fs-xs);
  color: var(--c-warning);
  background: var(--c-warning-soft);
  border-radius: var(--r-sm);
  padding: 1px var(--sp-2);
}
.dc-tag--info {
  color: var(--c-info);
  background: var(--c-surface-2);
}

/* ---------- 步骤时间线 ---------- */
.dc-steps {
  margin-top: var(--sp-2);
}
.dc-steps__toggle {
  display: inline-flex;
  align-items: center;
  gap: var(--sp-1);
  border: 0;
  background: transparent;
  color: var(--c-text-3);
  font-size: var(--fs-xs);
  padding: var(--sp-1) 0;
  border-radius: 0;
}
.dc-steps__toggle:hover:not(:disabled) {
  background: transparent;
  border-color: transparent;
  color: var(--c-primary);
}
.dc-steps__chevron {
  font-size: var(--fs-xs);
}
.dc-steps__list {
  list-style: none;
  margin: var(--sp-2) 0 0;
  padding: 0;
  border-top: 1px solid var(--c-border);
  max-height: 180px;
  overflow-y: auto;
}
.dc-steps__item {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) 0;
  border-bottom: 1px solid var(--c-border);
}
.dc-steps__item:last-child {
  border-bottom: 0;
}
.dc-steps__dot {
  width: 7px;
  height: 7px;
  border-radius: var(--r-full);
  background: var(--c-primary);
  margin-top: 5px;
  flex: 0 0 auto;
}
.dc-steps__item.is-success .dc-steps__dot {
  background: var(--c-success);
}
.dc-steps__item.is-danger .dc-steps__dot {
  background: var(--c-danger);
}
.dc-steps__item.is-warning .dc-steps__dot {
  background: var(--c-warning);
}
.dc-steps__text {
  flex: 1;
  min-width: 0;
}
.dc-steps__text strong {
  display: block;
  font-size: var(--fs-xs);
  color: var(--c-text-2);
  font-weight: 600;
}
.dc-steps__text small {
  display: block;
  font-size: var(--fs-xs);
  color: var(--c-muted);
  margin-top: 2px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.dc-steps__item time {
  font-size: var(--fs-xs);
  color: var(--c-muted);
  font-variant-numeric: tabular-nums;
  flex: 0 0 auto;
}

/* ---------- 操作按钮 ---------- */
.dc-task__actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--sp-2);
  margin-top: var(--sp-3);
}
.dc-btn {
  border: 1px solid var(--c-border);
  background: var(--c-surface);
  color: var(--c-text-2);
  font-size: var(--fs-xs);
  padding: var(--sp-1) var(--sp-3);
  border-radius: var(--r-sm);
}
.dc-btn:hover:not(:disabled) {
  background: var(--c-surface-2);
  border-color: var(--c-primary);
  color: var(--c-primary);
}
.dc-btn--primary,
.dc-btn--primary:hover:not(:disabled) {
  background: var(--c-primary-soft);
  border-color: var(--c-primary);
  color: var(--c-primary);
  font-weight: 600;
}
</style>
