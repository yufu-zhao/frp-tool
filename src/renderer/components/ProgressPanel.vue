<script setup lang="ts">
// 统一长任务进度：下载 / 证书签发 / 托管 TLS 实例都复用此组件。
// 支持百分比、速度、步骤时间线、取消、重试、关闭，并可插入额外内容（如 DNS-01 TXT 记录）。
import { computed } from 'vue';

interface ProgressStep {
  label: string;
  detail?: string;
  time?: number;
  tone?: string;
}

const props = withDefaults(
  defineProps<{
    title: string;
    status?: string;
    percent?: number | null;
    speed?: number | null;
    received?: number;
    total?: number;
    message?: string;
    steps?: ProgressStep[];
    cancellable?: boolean;
    retryable?: boolean;
    closable?: boolean;
    detail?: string;
    busy?: boolean;
  }>(),
  {
    status: 'running',
    percent: null,
    speed: null,
    cancellable: false,
    retryable: false,
    closable: false,
    busy: false,
  },
);
const emit = defineEmits<{
  (e: 'cancel'): void;
  (e: 'retry'): void;
  (e: 'close'): void;
}>();

const statusLabels: Record<string, string> = {
  starting: '准备中',
  downloading: '下载中',
  retrying: '重试中',
  paused: '已暂停',
  verifying: '校验中',
  extracting: '解压中',
  succeeded: '已完成',
  failed: '失败',
  cancelled: '已取消',
  running: '进行中',
  waiting: '等待中',
  completed: '已完成',
  cancelling: '取消中',
  'waiting-user': '等待操作',
};
const activeStates = [
  'starting',
  'downloading',
  'retrying',
  'verifying',
  'extracting',
  'running',
  'waiting',
  'waiting-user',
  'cancelling',
  'paused',
];
const doneStates = ['succeeded', 'completed', 'failed', 'cancelled'];

const isActive = computed(() => activeStates.includes(props.status));
const isDone = computed(() => doneStates.includes(props.status));
const isFail = computed(() => props.status === 'failed');
const tone = computed(() => (isFail.value ? 'danger' : isDone.value ? 'success' : 'running'));
const clamped = computed(() => Math.max(0, Math.min(100, Math.round(props.percent ?? 0))));

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
</script>

<template>
  <div class="progress-panel" :class="`progress-panel--${tone}`">
    <div class="progress-panel__head">
      <span v-if="isActive" class="progress-panel__spinner" aria-hidden="true"></span>
      <span v-else class="progress-panel__flag" aria-hidden="true">{{ isFail ? '!' : '✓' }}</span>
      <strong class="progress-panel__title">{{ title }}</strong>
      <span class="badge" :class="`badge--${tone}`">{{ statusLabels[status] || status }}</span>
      <button
        v-if="closable"
        class="progress-panel__close"
        type="button"
        aria-label="关闭"
        @click="emit('close')"
      >
        ×
      </button>
    </div>

    <p v-if="message" class="progress-panel__message">{{ message }}</p>

    <template v-if="percent !== null">
      <div
        class="progress-panel__track"
        role="progressbar"
        :aria-valuenow="clamped"
        aria-valuemin="0"
        aria-valuemax="100"
      >
        <div class="progress-panel__bar" :style="{ width: `${clamped}%` }"></div>
      </div>
      <div class="progress-panel__stats">
        <span class="progress-panel__percent">{{ clamped }}%</span>
        <span v-if="total">已传输 {{ fmtBytes(received) }} / 共 {{ fmtBytes(total) }}</span>
        <span v-if="speed">{{ fmtSpeed(speed) }}</span>
      </div>
    </template>

    <p v-if="detail" class="progress-panel__detail">{{ detail }}</p>
    <slot name="extra" />

    <ol v-if="steps && steps.length" class="progress-panel__timeline">
      <li v-for="(step, index) in steps" :key="index" :class="step.tone ? `is-${step.tone}` : ''">
        <span class="progress-panel__dot" aria-hidden="true"></span>
        <div class="progress-panel__step-text">
          <strong>{{ step.label }}</strong>
          <small v-if="step.detail">{{ step.detail }}</small>
        </div>
        <time v-if="step.time">{{ fmtTime(step.time) }}</time>
      </li>
    </ol>

    <div
      v-if="cancellable || (isFail && retryable) || (closable && isDone)"
      class="progress-panel__actions"
    >
      <button
        v-if="cancellable && !isDone"
        class="ui-btn ui-btn--ghost"
        type="button"
        :disabled="busy"
        @click="emit('cancel')"
      >
        取消
      </button>
      <button
        v-if="isFail && retryable"
        class="ui-btn ui-btn--primary"
        type="button"
        :disabled="busy"
        @click="emit('retry')"
      >
        重试
      </button>
      <button v-if="closable && isDone" class="ui-btn" type="button" @click="emit('close')">
        关闭
      </button>
    </div>
  </div>
</template>
