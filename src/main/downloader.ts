import { appendFile, mkdir, rm, stat, truncate } from 'node:fs/promises';
import path from 'node:path';
import type { DownloadProgress, DownloadRecord } from '../shared/types';
import { AppError, friendlyError } from '../shared/errors';
import type { Store } from './store';

// 与 versions.ts 中的 Fetcher 结构一致；所有请求仍走主进程注入的 fetcher。
export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

const MAX_PACKAGE = 200 * 1024 * 1024;
const DOWNLOAD_TIMEOUT = 120000;

export interface DownloadOptions {
  key: string;
  url: string;
  taskId: string;
  version: string;
  digest?: string;
  signal?: AbortSignal;
  onProgress?: (progress: DownloadProgress) => void;
}
export interface DownloadResult {
  partPath: string;
  received: number;
  total: number;
}

type Status = DownloadProgress['status'];
type ProgressBase = Pick<DownloadProgress, 'taskId' | 'key' | 'version'>;

export function progressEvent(
  base: ProgressBase,
  patch: Partial<DownloadProgress> & Pick<DownloadProgress, 'status' | 'message'>,
): DownloadProgress {
  const received = patch.received ?? 0;
  const total = patch.total ?? 0;
  return {
    ...base,
    // 透传 purpose / label / serverId 等发起方元数据，任务中心据此区分任务来源。
    ...patch,
    status: patch.status,
    message: patch.message,
    received,
    total,
    percent:
      patch.percent ??
      (total > 0 ? Math.min(100, Math.max(0, Math.round((received / total) * 100))) : 0),
    speed: patch.speed ?? 0,
    attempt: patch.attempt ?? 1,
    resumable: patch.resumable ?? false,
    updatedAt: Date.now(),
  };
}

export function emitProgress(
  onProgress: DownloadOptions['onProgress'],
  progress: DownloadProgress,
): void {
  try {
    onProgress?.(progress);
  } catch {
    // 界面进度通道异常不应中断下载。
  }
}

function headerValue(response: Response, name: string): string | undefined {
  try {
    const headers = (response as { headers?: unknown }).headers as
      { get(name: string): string | null } | Record<string, string> | undefined;
    if (!headers) return undefined;
    if (typeof (headers as { get?: unknown }).get === 'function')
      return (headers as { get(name: string): string | null }).get(name) ?? undefined;
    const record = headers as Record<string, string>;
    return record[name] ?? record[name.toLowerCase()] ?? undefined;
  } catch {
    return undefined;
  }
}

// 把外部取消信号与单次请求超时合并，并保留 abort reason（用于区分暂停与放弃）。
function combinedSignal(external?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(DOWNLOAD_TIMEOUT);
  if (!external) return timeout;
  const controller = new AbortController();
  timeout.addEventListener('abort', () => controller.abort(timeout.reason), { once: true });
  external.addEventListener('abort', () => controller.abort(external.reason), { once: true });
  if (external.aborted) controller.abort(external.reason);
  return controller.signal;
}

function backoff(attempt: number): number {
  return Math.min(2000, 200 * 2 ** (attempt - 1));
}

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new AppError('下载已暂停，已保留断点，可稍后继续。', 'DOWNLOAD_PAUSED'));
      },
      { once: true },
    );
  });
}

async function* bodyChunks(body: unknown): AsyncGenerator<Buffer> {
  if (!body) return;
  const value = body as Record<symbol | string, unknown>;
  if (typeof value[Symbol.asyncIterator] === 'function') {
    for await (const chunk of body as AsyncIterable<Uint8Array | string | Buffer>) {
      yield Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array | string);
    }
    return;
  }
  if (typeof value[Symbol.iterator] === 'function' && !Buffer.isBuffer(body)) {
    for (const chunk of body as Iterable<Uint8Array>) yield Buffer.from(chunk);
    return;
  }
  if (typeof body === 'string') yield Buffer.from(body);
  else if (body instanceof Uint8Array) yield Buffer.from(body);
}

interface State {
  received: number;
  total: number;
  etag?: string;
  lastModified?: string;
  attempt: number;
  resumable: boolean;
}

export class Downloader {
  constructor(
    private store: Store,
    private fetcher: Fetcher,
  ) {}

  // 稳定路径：downloads/<versionKey>.part，绝不放在 packages/ 下。
  partPath(key: string): string {
    const safe = key.replace(/[^a-zA-Z0-9_.-]/g, '_');
    return path.join(this.store.root, 'downloads', `${safe}.part`);
  }

  async download(options: DownloadOptions): Promise<DownloadResult> {
    const { key, url, taskId, version, digest, signal, onProgress } = options;
    const part = this.partPath(key);
    await mkdir(path.dirname(part), { recursive: true, mode: 0o700 });

    const base: ProgressBase = { taskId, key, version };
    const state: State = { received: 0, total: 0, attempt: 1, resumable: false };
    const record = this.store.data.downloads.find((item) => item.key === key);
    if (record) {
      state.etag = record.etag;
      state.lastModified = record.lastModified;
      state.total = record.total ?? 0;
    }
    // 以分片实际长度为准：写入的每个 chunk 都是完整的，崩溃后也能安全续传。
    let onDisk = 0;
    try {
      onDisk = (await stat(part)).size;
    } catch {
      onDisk = 0;
    }
    state.received = onDisk;
    // 联网下载始终写入稳定 .part，天然支持断点续传。
    state.resumable = true;

    let lastPersistAt = 0;
    const persist = async (status: DownloadRecord['status'], force = false) => {
      const now = Date.now();
      if (!force && now - lastPersistAt < 500) return;
      if (!force && state.received === 0 && !record) return;
      lastPersistAt = now;
      await this.store.saveDownload({
        key,
        url,
        digest,
        partPath: part,
        received: state.received,
        total: state.total,
        etag: state.etag,
        lastModified: state.lastModified,
        status,
        updatedAt: now,
      });
    };

    let lastSampleAt = Date.now();
    let lastSampleReceived = state.received;
    let speed = 0;
    const report = (status: Status, message: string, patch: Partial<DownloadProgress> = {}) => {
      const now = Date.now();
      if (status === 'downloading') {
        const seconds = (now - lastSampleAt) / 1000;
        if (seconds >= 0.25) {
          speed = Math.max(0, Math.round((state.received - lastSampleReceived) / seconds));
          lastSampleAt = now;
          lastSampleReceived = state.received;
        }
      }
      emitProgress(
        onProgress,
        progressEvent(base, {
          status,
          message,
          received: state.received,
          total: state.total,
          speed,
          attempt: state.attempt,
          resumable: state.resumable,
          ...patch,
        }),
      );
    };

    // 取消/暂停的统一出口：暂停保留断点与记录，放弃则清理并上报 cancelled。
    const abortNow = async (): Promise<never> => {
      if (signal?.reason === 'discard') {
        report('cancelled', '下载已取消，临时文件已清理。');
        await rm(part, { force: true });
        await this.store.dropDownload(key);
        throw new AppError('下载已取消。', 'DOWNLOAD_CANCELLED');
      }
      report('paused', '下载已暂停，已保留断点，可稍后继续。');
      if (state.received > 0 || record) await persist('paused', true);
      throw new AppError('下载已暂停，已保留断点，可稍后继续。', 'DOWNLOAD_PAUSED');
    };

    report(
      'starting',
      state.received > 0
        ? `发现未完成的下载，从 ${state.received} 字节处继续。`
        : '开始下载安装包。',
    );
    if (signal?.aborted) await abortNow();
    if (state.received > 0 || record) await persist('downloading', true);

    // 分片已完整（例如上次解压阶段失败），直接复用，无需重复联网。
    if (record && record.total > 0 && state.received >= record.total) {
      state.received = record.total;
      state.total = record.total;
      state.resumable = false;
      report('downloading', '本地分片已完整，直接校验安装包。', { percent: 100 });
      await persist('succeeded', true);
      return { partPath: part, received: state.received, total: state.total };
    }

    const retries = Math.max(0, Math.min(10, this.store.data.settings?.downloadRetries ?? 3));
    for (let attempt = 1; attempt <= retries + 1; attempt++) {
      state.attempt = attempt;
      if (signal?.aborted) await abortNow();
      try {
        await this.attempt(options, part, state, report, persist);
        if (!state.total || state.total < state.received) state.total = state.received;
        if (state.total > 0 && state.received < state.total)
          throw new AppError('安装包下载不完整，将自动重试。', 'DOWNLOAD_RETRYABLE');
        report('downloading', '安装包下载完成，准备校验。', { percent: 100 });
        await persist('succeeded', true);
        return { partPath: part, received: state.received, total: state.total };
      } catch (error) {
        if (signal?.aborted || (error instanceof AppError && error.code === 'DOWNLOAD_PAUSED'))
          await abortNow();
        const permanent =
          error instanceof AppError &&
          (error.code === 'DOWNLOAD_FAILED' || error.code === 'PACKAGE_TOO_LARGE');
        if (permanent || attempt >= retries + 1) {
          report('failed', friendlyError(error));
          if (state.received > 0 || record) await persist('failed', true);
          throw error;
        }
        report('retrying', `${friendlyError(error)}，准备第 ${attempt + 1} 次尝试。`);
        if (state.received > 0 || record) await persist('failed', true);
        await wait(backoff(attempt), signal);
        // 重新读取分片长度，从新断点继续。
        try {
          state.received = (await stat(part)).size;
        } catch {
          state.received = 0;
        }
        state.resumable = true;
      }
    }
    throw new AppError('安装包下载失败。', 'DOWNLOAD_FAILED');
  }

  private async attempt(
    options: DownloadOptions,
    part: string,
    state: State,
    report: (status: Status, message: string, patch?: Partial<DownloadProgress>) => void,
    persist: (status: DownloadRecord['status'], force?: boolean) => Promise<void>,
  ): Promise<void> {
    const headers: Record<string, string> = {
      Accept: 'application/octet-stream',
      'User-Agent': 'Intranet-FRP-Desktop',
    };
    if (state.received > 0) {
      headers.Range = `bytes=${state.received}-`;
      const validator = state.etag ?? state.lastModified;
      if (validator) headers['If-Range'] = validator;
    }
    const response = await this.fetcher(options.url, {
      headers,
      signal: combinedSignal(options.signal),
    });
    const partial = response.status === 206;
    const full = response.ok && !partial;
    if (!partial && !full) {
      try {
        await (response.body as unknown as { cancel?: () => Promise<void> })?.cancel?.();
      } catch {
        // 忽略无法关闭的响应体。
      }
      const retryable =
        response.status === 408 || response.status === 429 || response.status >= 500;
      throw new AppError(
        `安装包下载失败（HTTP ${response.status}），可重试或改用离线导入。`,
        retryable ? 'DOWNLOAD_RETRYABLE' : 'DOWNLOAD_FAILED',
      );
    }

    const etag = headerValue(response, 'etag');
    const lastModified = headerValue(response, 'last-modified');
    if (etag) state.etag = etag;
    if (lastModified) state.lastModified = lastModified;
    const contentLength = Number(headerValue(response, 'content-length') ?? 0) || 0;
    const contentRange = headerValue(response, 'content-range');
    let rangeStart = -1;
    let rangeTotal = 0;
    if (contentRange) {
      const match = contentRange.match(/bytes\s+(\d+)-\d+\/(\d+|\*)/i);
      if (match) {
        rangeStart = Number(match[1]);
        if (match[2] !== '*') rangeTotal = Number(match[2]);
      }
    }

    if (partial) {
      // 206：服务端从 rangeStart 返回剩余数据，追加到本地分片。
      if (rangeStart > state.received)
        throw new AppError('断点位置与服务端不一致，将重新尝试。', 'DOWNLOAD_RETRYABLE');
      if (rangeStart >= 0 && rangeStart < state.received) {
        await truncate(part, rangeStart);
        state.received = rangeStart;
      }
      state.total = rangeTotal || state.received + contentLength || state.total;
    } else {
      // 200：服务端不支持 Range，丢弃旧分片从头覆盖。
      if (state.received > 0) {
        await rm(part, { force: true });
        state.received = 0;
      }
      state.total = contentLength || state.total;
    }
    if (state.total > MAX_PACKAGE) throw new AppError('安装包超过大小限制。', 'PACKAGE_TOO_LARGE');

    const body = (response as { body?: unknown }).body;
    if (!body) throw new AppError('安装包为空或超过大小限制。', 'DOWNLOAD_RETRYABLE');
    let got = false;
    for await (const chunk of bodyChunks(body)) {
      got = true;
      if (options.signal?.aborted)
        throw new AppError('下载已暂停，已保留断点，可稍后继续。', 'DOWNLOAD_PAUSED');
      if (state.received + chunk.length > MAX_PACKAGE)
        throw new AppError('安装包超过大小限制。', 'PACKAGE_TOO_LARGE');
      await appendFile(part, chunk);
      state.received += chunk.length;
      if (state.total && state.received > state.total) state.total = state.received;
      report('downloading', '正在下载安装包。');
      await persist('downloading');
    }
    if (!got && state.received === 0)
      throw new AppError('安装包为空或超过大小限制。', 'DOWNLOAD_RETRYABLE');
  }
}
