<script setup lang="ts">
// 轻量代码编辑器：行号、语法高亮、搜索/替换与保存快捷键。
// 通过 compartment 响应语言/只读状态变化，避免重建编辑器导致光标跳动。
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { basicSetup } from 'codemirror';
import { Compartment, EditorState } from '@codemirror/state';
import { EditorView, keymap } from '@codemirror/view';
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { openSearchPanel } from '@codemirror/search';
import { tags } from '@lezer/highlight';
import { nginx } from '@codemirror/legacy-modes/mode/nginx';

type Flavor = 'nginx' | 'apache' | 'caddy' | 'lighttpd' | 'unknown';

const props = withDefaults(
  defineProps<{
    modelValue: string;
    flavor?: Flavor;
    height?: string;
    readonly?: boolean;
    loading?: boolean;
  }>(),
  { flavor: 'unknown', height: '420px', readonly: false, loading: false },
);

const emit = defineEmits<{
  (event: 'update:modelValue', value: string): void;
  (event: 'save'): void;
}>();

const host = ref<HTMLElement | null>(null);
const languageCompartment = new Compartment();
const readonlyCompartment = new Compartment();
let view: EditorView | undefined;

const genericConfig = StreamLanguage.define({
  name: 'site-config',
  token(stream) {
    if (stream.sol() && stream.match(/^\s*#/)) {
      stream.skipToEnd();
      return 'comment';
    }
    if (stream.eatSpace()) return null;
    if (stream.match(/^"(?:[^"\\]|\\.)*"/) || stream.match(/^'(?:[^'\\]|\\.)*'/)) return 'string';
    if (stream.match(/^\b\d+(?:\.\d+)?\b/)) return 'number';
    if (stream.match(/^[{}[\]();,]/)) return 'bracket';
    if (stream.match(/^[A-Za-z_][\w-]*(?=\s|=)/)) return 'keyword';
    stream.next();
    return null;
  },
});

function languageFor(flavor: Flavor) {
  return flavor === 'nginx' ? StreamLanguage.define(nginx) : genericConfig;
}

const highlight = HighlightStyle.define([
  { tag: tags.comment, color: 'var(--c-text-3)', fontStyle: 'italic' },
  { tag: tags.keyword, color: 'var(--c-purple)' },
  { tag: tags.string, color: 'var(--c-success)' },
  { tag: tags.number, color: 'var(--c-warning)' },
  { tag: tags.propertyName, color: 'var(--c-primary)' },
  { tag: tags.bracket, color: 'var(--c-text-2)' },
]);

const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    backgroundColor: 'var(--c-surface)',
    color: 'var(--c-text)',
    fontSize: 'var(--fs-sm)',
  },
  '.cm-scroller': {
    fontFamily: 'var(--font-mono)',
    lineHeight: '1.6',
    overflow: 'auto',
  },
  '.cm-content': { padding: '12px 0', caretColor: 'var(--c-primary)' },
  '.cm-line': { padding: '0 12px' },
  '.cm-gutters': {
    backgroundColor: 'var(--c-surface-2)',
    color: 'var(--c-text-3)',
    borderRight: '1px solid var(--c-border)',
  },
  '.cm-activeLine': { backgroundColor: 'var(--c-primary-soft)' },
  '.cm-activeLineGutter': {
    backgroundColor: 'var(--c-primary-soft)',
    color: 'var(--c-primary-ink)',
  },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
    backgroundColor: 'var(--c-focus)',
  },
  '.cm-cursor': { borderLeftColor: 'var(--c-primary)' },
  '.cm-panels': {
    backgroundColor: 'var(--c-surface-2)',
    color: 'var(--c-text)',
    borderColor: 'var(--c-border)',
  },
  '.cm-panel input, .cm-panel button': {
    fontFamily: 'var(--font)',
    fontSize: 'var(--fs-sm)',
  },
});

const shortcuts = () =>
  keymap.of([
    {
      key: 'Mod-f',
      preventDefault: true,
      run: () => {
        if (view) openSearchPanel(view);
        return true;
      },
    },
    {
      key: 'Mod-h',
      preventDefault: true,
      run: () => {
        if (!view) return true;
        openSearchPanel(view);
        const root = view.dom.parentElement ?? view.dom;
        root.querySelector<HTMLInputElement>('input[name="replace"]')?.focus();
        return true;
      },
    },
    {
      key: 'Mod-s',
      preventDefault: true,
      run: () => {
        emit('save');
        return true;
      },
    },
  ]);

function createState() {
  return EditorState.create({
    doc: props.modelValue,
    extensions: [
      shortcuts(),
      basicSetup,
      languageCompartment.of(languageFor(props.flavor)),
      readonlyCompartment.of([
        EditorState.readOnly.of(props.readonly),
        EditorView.editable.of(!props.readonly),
      ]),
      syntaxHighlighting(highlight),
      editorTheme,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) emit('update:modelValue', update.state.doc.toString());
      }),
    ],
  });
}

onMounted(() => {
  if (!host.value) return;
  view = new EditorView({ state: createState(), parent: host.value });
});

watch(
  () => props.modelValue,
  (value) => {
    if (!view || value === view.state.doc.toString()) return;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } });
  },
);

watch(
  () => props.flavor,
  (flavor) => {
    view?.dispatch({ effects: languageCompartment.reconfigure(languageFor(flavor)) });
  },
);

watch(
  () => props.readonly,
  (readonly) => {
    view?.dispatch({
      effects: readonlyCompartment.reconfigure([
        EditorState.readOnly.of(readonly),
        EditorView.editable.of(!readonly),
      ]),
    });
  },
);

onBeforeUnmount(() => {
  view?.destroy();
  view = undefined;
});
</script>

<template>
  <div class="site-code-editor" :style="{ height }">
    <div ref="host" class="site-code-editor__host"></div>
    <div v-if="loading" class="site-code-editor__loading">
      <span class="ui-spinner"></span>
      正在读取服务器配置…
    </div>
    <p class="site-code-editor__hint">提示：Ctrl+F 搜索关键字，Ctrl+H 查找替换，Ctrl+S 保存。</p>
  </div>
</template>
