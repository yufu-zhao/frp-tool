# Intranet / 穿透工作台 项目约定

## 协作方式

- 先讨论、达成一致后再动代码；功能调整先评估能否复用现有实现，避免重复造。
- 每次页面调整后覆盖桌面 1440 / 平板 1024 / 窄窗口 900 三档布局检查（Electron 桌面应用，无手机端）。
- **用户要"全新 UI"时的底线**：必须真正从零设计一套，而不是在旧风格上打补丁；用户已明确表达过对"应付式优化"的不满（后续已否决重做，见下方「当前生效 UI」，视觉改动一律走原版定点修正）。
- **实拍前必须重新构建**：Electron 回归脚本用 `loadFile(dist/renderer/index.html)`，改了 `src/renderer` 源码后不 `npm run build` 就截图会看到旧界面，容易误判"改动没生效"。

## 当前生效 UI：src/renderer（2026-11-26 用户否决全新 UI 后回退）

- `src/ui2/` 整套已被用户否决并物理删除（用户："还不如原来的"），`vite.config.ts` 的 root 已改回 `src/renderer`。下方「Graphite + Indigo」「终端页」等约定重新生效。
- **不要再提"全新 UI / 重做一套"**：用户已明确表示这类改动是应付式换皮且观感更差。视觉相关只做原版上的定点修正，并先实拍确认问题真实存在再动手。
- 曾适配 ui2 的回归脚本已全部还原到原版选择器（`.nav-item` 等），`scripts/visual-check-v2.mjs` / `artifacts/visual-v2/` 已删除。
- 终端「记录」列表在 `parseShellHistory()` 按命令去重、保留最近一次（`src/main/service-discovery.ts`）；重复的 history/ll 不再刷屏。
- 2026-11-26 已按用户 9 张截图完成原版定点修复（表单对齐/折叠路径/按钮统一/规则标签/SSL 面板/DNS 行卡片/证书抽屉/终端三处/卡片间距），详见当天日志。新增可复用实拍脚本 `scripts/visual-audit.mjs`（9 张，`artifacts/audit/`）与 `scripts/terminal-audit.mjs`（终端会话态 DOM 注入验证）；**别再把这些改动扩成整套 UI 重做**。
- 界面文案改动后要同步 Electron 回归脚本断言：`electron-smoke.mjs` / `rule-editor-check.mjs` 的 DNS 按钮现已带「＋」前缀，`server-panel-check.mjs` 的部署路径默认折叠需先展开。

## 设计系统 Graphite + Indigo（2026-11-26 用户拍板，界面重构基线）

- **中性 + 单一强调色**：中性石墨 N0–N900 承载信息层级；唯一品牌色靛蓝 `#5457E5`（dark `#6d70f0`，hover/按下/soft 四档），按钮/选中态/链接/进度只用它。语义色（success/warning/danger/info）刻意降饱和，不与强调色冲突。暖色（红/橙/绿）和青碧/亮紫已评估但未采用：前者与语义色打架，后者需额外明度/面积约束。
- **硬规范**：字重只有 400 / 500（不用 600/650/700）；圆角 6（控件）/10（卡片）/14（面板）；间距 4 倍数；阴影更轻更扩散；扁平无渐变（进度条也用纯色）。`style.css` 的 `:root` token 与 `antdTheme`（App.vue）必须同步。
- **导航**：菜单项少，`AppSidebar` 扁平平铺 8 项 + 内联线性 SVG 图标，禁止恢复分组折叠；窄窗口（≤1100px）与手动折叠都收成图标条。
- **终端页**：`terminal-workspace` 固定 `calc(100vh - 168px)` + overflow hidden；快捷命令/记录 `.shortcut-list` `max-height:34vh` 内部滚动；输出区 `.terminal-main` `min-height:0`。任何内容区都不能把容器撑得无限高（`terminal-layout-check.mjs` 守卫）。
- **交互收敛**：同一操作只保留一个入口（header 主按钮优先，EmptyState/页底不放重复按钮）；去掉纯说明性冗余提醒文案；DNS 各 tab 自带按钮，header 不放错位的主按钮。
- **按钮分层**：详情页任一时刻只保留一个主色按钮，按连接/部署状态切换主次（未连接时连接类操作为主，已连接后部署/启停类操作为主，禁用态一律降为 soft）；无意义按钮按状态隐藏而非禁用占位；低频操作（读配置/备份等）收进 `details` 折叠区，危险操作单独置底。
- **设计系统硬约束**：CSS 变量必须在 `:root` 定义后才能引用，禁止残留 `--color-*` / `--border-radius-*` 旧变量（曾导致 40+ 处样式静默失效）；全局 `label` 默认 `inline-flex/row`，只有 `.field` 容器内 label 才列向，避免内联开关文字竖排。状态徽标放标题旁同一基线、只显示一次（不在 header 和侧栏重复）。空态不显示空表头。页面调整必须做全页审计（间距/对齐/层级/组件用法），不能只改用户点名的元素。
- **应用图标 A「链路 Nexus」**：母版 `assets/brand/logo.svg` / `glyph.svg`（靛蓝渐变方块 + 白色弧线贯通两端节点，终点薄荷绿）；`npm run icons` 从母版生成全尺寸 PNG/ICO/ICNS/三态托盘/preview，`icons.mjs` 用 `replaceAll` 处理多色节点。
- 验证入口：`npm run test:ui` = 终端限高 + 三档×四页视觉巡检（截图 `artifacts/visual/`）；`scripts/electron-smoke.mjs` 等四个回归脚本随 UI 文案同步更新。

## TLS 方案判定与证书入口（2026-11-26 用户确认，取代此前按 Web 探测决定方案）

- 方案只由服务端配置的 `vhostHTTPPort`（`server.httpPort`）决定：标准 80 → 方案 B（本机 frpc 终止）；非标端口 → 方案 A（服务器 Web 服务终止）。端口未知按 A 并阻止申请。
- Web 服务、include 注入记录、default.conf 探针**只作为方案 A 的申请门槛**，任一失败即阻止申请（界面禁用 + 主进程报错），不自动降级为 B；443 占用、权限等只提示。
- 侧栏「本机 SSL」改为「证书管理」，只读展示；申请 / 导入 / 移除证书只在客户端实例的 Web 规则 SSL 面板中操作。HTTP-01 文件验证不展示实例选择，按规则所属实例或目标服务器唯一实例自动确定。
- 菜单移除「TLS 入口」，设置页移除托管实例开关；后端托管 TLS IPC 保留但界面不接入。
- **HTTP/HTTPS 共存（用户反复强调）**：一个站点规则，规则列表只显示一条；有证书时 HTTP(80) 与 HTTPS(443) 两个 server 块必须同时存在，不能用 443 替换掉 80。方案 A 模板（`generateSiteConfig` tlsMode=server / `nginxTlsServerConfig`）都输出两块；已部署旧配置只有 443 时用 `mergeTlsSiteConfig()` 补齐 HTTP 块。规则数据层：方案 A = 一条 `http + publicHttps=true`，方案 B = 一条可见 http + 隐藏 https 伴随规则，列表都只一条，不要为此新增可见规则。

## 端口与 TLS 基线（2026-11-24 用户重新拍板，取代旧的「永不使用 80/443」硬约束）

- `vhostHTTPPort` / `vhostHTTPSPort`（`server.httpPort` / `server.httpsPort`）**按服务器现状手填**；80/443 空闲时 frps 可直接占用，不必强制高端口。
- **本机可持有证书**。80/443 空闲时链路为 `frps:80/443 → frpc → 本机服务/证书`，服务器侧不需要证书或反代。
- 80/443 被占用时 frps 用高端口：现有 Web 层终止 TLS，或把 HTTP-01 challenge 路径反代到 frps 高端口 → frpc 临时响应器；持有者不可控（Docker DNAT、面板、未知服务）时用 DNS-01 + 输出配置片段。
- 安装 nginx / Docker Web 前，用户会**手动卸载本工具释放端口**；工具只需保证清单驱动干净卸载与残留报告，不再把自动让位 / 迁移当必需路径。
- 托管 TLS 实例仍不得与 frps HTTP 入口同为 80/443（避免自身端口冲突），但这条只约束托管实例。
- 申请 SSL 证书不得影响服务端 80/443 的正常使用；DNS-01 不依赖端口。

## 本机 SSL 最小 MVP（2026-11-25 用户确认，取代下方旧证书逻辑）

- 用户明确“不考虑之前定的任何逻辑”，只做本机申请 + 本机部署的可测 MVP。
- `server-certificates.ts` 单一 `issue()`：固定 DNS-01 + 已保存账户 → ACME 签发 → 本机证书库 → 自动关联同服务器域名匹配的 HTTPS 规则（terminate）；签发与部署共用一个 `taskId` 进度，失败回滚 DNS TXT / 规则快照 / store 记录 / 本机证书目录。
- `store.schema` 升到 3：升级时清空旧 `certificates` / `serverCertificates` / `serverSites`，清除 HTTPS 规则旧引用并删本机 `certificates/` 目录。页面与侧栏改名“本机 SSL”。
- HTTP-01 反代、部署级别、环境复核、续期调度、手动导入暂不实现，等用户实测反馈再决定。
- 下方“证书方案（已落地）”仅作历史记录，不要再按它实现新功能。

## 证书方案（历史记录，已被上方 MVP 取代）

- 证书申请：DNS-01 与 HTTP-01 两种都要。DNS-01 逐级自动化（选中 DNS 账户 API → CNAME 委派/acme-dns → 复用已有记录 → 手动 TXT 兜底），任一级失败自动降级并标明级别；手动 TXT 明确半自动。
- **DNS 账户**：可保存多个账户，同一服务商也可多份 SecretID；凭据只存 `dns:account:<id>:*`，签发选账户、续期沿用 `dnsAccountId`。A1/A2/A3 优先读选中账户凭据。
- **ACME 配置**：LiteSSL EAB KID/HMAC 与联系邮箱集中在设置；EAB 只存安全存储，邮箱首次签发后回写设置并自动读取。ACME 账户密钥必须绑定当前 EAB 指纹（`acme:<provider>:accountKeyEab`），EAB 变化即换密钥重新注册，否则 CA 报 "The client lacks sufficient authorization"；显式重填 EAB 保存时主动清除账户密钥强制重注册。
- 证书实体：`serverCertificateSchema` / `serverCertificates` / `renewalManager`；`location: 'local' | 'server'`（默认 server）+ `localCertificateId` 区分证书落点，本机也允许持证书，不再限定「本机不持证书」。
- **本机证书闭环（已落地）**：80/443 空闲（`httpsPort === 443 || httpPort === 80`）签发的证书落本机证书库（`Certificates.saveIssued()`），直接标 `deployed` / `deployTarget = 'local-frpc'`，无需部署到服务端；`instance:save` 在 `httpsPort === 443` 时自动关联到 HTTPS 规则并设 `tlsMode = 'terminate'`；frpc 用 `https2http` 插件引用本机证书（`processes.certificatePaths()` 同时读取 `certificates` 与 `serverCertificates` 中 `location === 'local'` 的记录）。续期沿用原落点，需关注对运行中 frpc 是否要重载。
- 证书部署分级（仅针对 `location === 'server'` 的服务端证书；本机证书不部署）：L0 只落盘+给配置片段；L1 同路径覆盖已有证书文件；L2 在 include 目录写独立 conf（二次确认、快照 diff、失败回滚）。主配置绝不改、绝不 stop/restart。
- 生命周期：无 80/443 持有者时标记「待部署」；状态机：已签发·待部署 → 待确认 → 已生效 → 需复核 → 回到确认。续期用服务端 systemd timer / cron；复用 `server-sites.ts` 的备份 / `nginx -t` / 回滚事务框架，`insertHttpInclude` 弃用。

## 全新服务器：工具托管临时 TLS 实例（2026-11-24 补充）

- 「没有 nginx、80/443 空闲」指的是**全新未装任何软件的服务器**。用户要求：工具可临时建立 nginx 服务，随时一键卸载并清除所有相关内容，且**不能影响服务器日后正常安装使用 nginx 等软件**。
- 原约束「frps 不得占 80/443」仅针对 frps；托管 TLS 实例可临时持有 80/443，但必须能随时释放。
- 隔离原则：绝不触碰 `/etc/nginx`、`/usr/sbin/nginx`、`nginx.service`、apt/yum 包数据库、`/var/log/nginx`、`/etc/letsencrypt`、系统用户/组、PATH、sudoers、持久防火墙规则。全部资源放在 `~/.local/share/intranet-frp/tls-proxy/` 独立目录，独立 `nginx -p` prefix、独立 pid/logs/证书目录、独立 unit 名 `intranet-frp-tls`。
- 一键卸载采用**清单驱动**：安装时把每个创建的资源写入 `state.json`，卸载按清单逆序清理，只删带应用标记且未被用户改动的资源；卸载前后做资源快照对比，残留可重试/导出报告。提供「仅停止并释放端口（让位）」与「完全卸载」两种粒度。
- 让位：探测到用户装了系统 nginx 或 80/443 归属变化时，主动提示停止托管实例、释放端口、把证书与反代配置迁移过去，绝不抢端口导致系统 nginx 起不来。
- 证书申请与本实例解耦：DNS-01 不需要 80/443，全新服务器也能先申请证书；托管实例负责让 HTTPS 访问真正可用。
- 选型已定（2026-11-24 用户确认）：**B 工具自带单文件静态 TLS 反代**，Go 编写并交叉编译为 `assets/bin/tls-proxy-linux-{amd64,arm64}`；「临时」= 工具托管、常驻到一键卸载为止。C 系统包安装、D Docker 均排除。该方案已实现，详见当天日志。

## 全量改造已落地（2026-11-24）

- 方案已从讨论进入实现。新增主进程模块：`server-certificates.ts`（服务端证书生命周期/部署状态机）、`dns-automation.ts`（A1–A4 逐级降级）、`site-inspector.ts`（只读站点检查）、`tls-proxy.ts`（托管实例 + 清单驱动卸载）、`downloader.ts`（Range 断点续传 + 进度事件）、`contracts.ts`（统一 IPC 契约）。
- 版本库：目录缓存持久化并启动秒开（`store.saveCatalog` / `versions.cachedCatalog`）；下载有进度、可取消、失败保留 `.part` 续传。
- UI：`App.vue` 全量重写 + `components/` 统一交互组件 + `style.css` 响应式；确认/弹窗/Toast/进度全部移到渲染层；设置与帮助同步新架构。
- 验收习惯落地：桌面冒烟测试脚本 + 逐页多视口布局巡检；`FormField` 标签与控件必须保持 `for`/`id` 关联（可访问性与自动化定位）。

## 技术栈与结构

- Electron + Vue3 + TS + FRP；`src/main` 主进程、`src/renderer` 渲染、`src/shared` 共享类型、`src/preload` 只暴露固定 IPC。
- 本机受限环境的启动方式见 `2026-11-24.md` 日志。

## 产品边界（2026-11-24 用户确认）

- 本工具**只有桌面端**，不做手机视口适配；窗口拖窄时只需保证不溢出（侧栏图标条 + 表单单列），不要再引入抽屉/汉堡/全屏弹窗。
- 已移除的入口：服务器站点、本机证书（旧模式）、使用向导。后续不要再加回来。
- HTTPS 规则的 TLS 终止位置按上方 2026-11-26 的 `vhostHTTPPort` 规则判定，不再按 Web 探测结果决定。
- 证书管理页只保留证书列表 / 卡片（已简化并支持搜索、分页）；详情用 `AppDrawer` 抽屉显示证书/私钥内容与真实存放位置，支持下载与删除。ACME 邮箱与 EAB 在设置页维护，签发弹窗只选已保存账户。已保存的 EAB / DNS 账户凭据只以脱敏摘要作为输入框 placeholder，明文绝不回渲染层。
- **DNS 管理（2026-11-26 用户确认）**：DNS 账户已从设置页移到独立的「DNS 管理」工作台菜单，页面用标签页组织，**域名解析管理在前、账户管理在后**。解析管理做完整 CRUD（选账户→选域名→列/增/改/删记录），复用 `dns-automation.ts` 中 DNSPod/阿里云/Cloudflare 三家适配器；设置页不再有 DNS 账户入口。签发弹窗仍只选已保存账户。
- 服务端证书与托管 TLS 依赖 `certificates.ts` 签发引擎和 `server-sites.ts` nginx 事务框架，删除其他功能时必须保留这两块。

## 版本管理方案（2026-11-24 用户确认）

- 版本选择下沉到使用点：服务端安装按 SSH 探测的 Linux 架构自动选最新稳定版；客户端版本号跟随所选服务器部署版本、架构按本机；服务器未部署时取最新稳定版并提示。缺包自动下载 + 校验 + 安装，显示进度。
- 启动**只读 state.json 回显版本列表，绝不自动联网**；联网只在用户手动点「获取 / 刷新列表」时发生。文案用「来源 + 列表更新于 + 已保存到本机」，不再写「使用缓存 / 缓存时间」。
- 进度用应用内**右下角常驻任务中心**（跨页面、可收起、多任务），不做独立 Electron 窗口；其 z-index 必须低于弹窗 / 确认框，避免遮挡按钮。点击即刻本地 seed 任务，不等 IPC。
- 危险操作确认一律在渲染层；主进程取不到 SHA256 时抛 `CHECKSUM_UNAVAILABLE`，由渲染层弹确认后带 `confirmed` 重试，禁止弹 Electron 原生框阻塞界面。
- 长任务（下载）不得占用全局 `busy`，否则取消 / 其它操作会被门闩吞掉。
