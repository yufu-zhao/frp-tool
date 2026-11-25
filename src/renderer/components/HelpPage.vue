<script setup lang="ts">
// 帮助独立成页。内容按新架构组织：端口约束、证书终止位置、证书管理、
// 断点续传、常见问题。纯展示，无状态。
import SectionCard from './SectionCard.vue';
import StatusBadge from './StatusBadge.vue';

withDefaults(defineProps<{ platform?: string }>(), { platform: '' });
</script>

<template>
  <div class="help-page">
    <SectionCard
      title="使用路径"
      description="按工作流分组组织：先准备基础设施，再建立穿透，随后申请与管理证书，最后用工具排障。"
    >
      <ol class="help-flow">
        <li>
          <b>基础设施</b><span>添加服务器；FRP 版本在服务端安装与创建客户端时自动选择并补齐</span>
        </li>
        <li><b>穿透</b><span>创建客户端实例与代理规则，把本地服务映射到服务器高端口入口</span></li>
        <li><b>证书</b><span>在 Web 规则中申请或导入证书，在证书管理页查看部署位置</span></li>
        <li><b>工具</b><span>用 SSH 终端与快捷命令排障，在设置中调整默认行为</span></li>
      </ol>
    </SectionCard>

    <div class="help-grid">
      <SectionCard title="端口选择" description="按服务器现有 80 / 443 的占用情况决定。">
        <div class="help-ports">
          <div>
            <StatusBadge tone="info" label="FRP 入口端口" :dot="false" />
            <p>
              HTTP / HTTPS vhost 入口按服务器现状手填：80 / 443
              空闲时可直接占用，被占用时改用高端口，如 8080 / 8443。
            </p>
          </div>
          <div>
            <StatusBadge tone="success" label="公网 80 / 443" :dot="false" />
            <p>由服务器原有 Web 服务或工具托管的 TLS 实例持有，用于对外提供标准 HTTPS。</p>
          </div>
          <div>
            <StatusBadge tone="info" label="FRP 7000" :dot="false" />
            <p>服务端与客户端的连接端口；实际入口端口、云安全组与系统防火墙需自行放行。</p>
          </div>
        </div>
        <p class="help-note">本工具不会自动修改防火墙或云安全组规则。</p>
      </SectionCard>

      <SectionCard title="端口与 TLS 终止位置" description="按服务器现状选择，不再固定高端口。">
        <p>
          方案只由服务端配置中的 <code>vhostHTTPPort</code> 决定：标准 80 端口使用方案
          B，证书保存在本机，由 frpc 的 <code>https2http</code> 终止 TLS；非标端口（如
          8080）使用方案 A，证书写入服务器并由服务器 Web 服务终止 TLS。HTTP-01 文件验证自动使用当前
          Web 规则所属的客户端实例，无需手选。
        </p>
        <p>
          方案 A 申请前必须满足三项条件：检测到服务器 Web 服务、已注入 include、default.conf
          探针生效；任一失败会阻止申请，不会自动降级为方案 B。DNS-01 在「设置 → DNS
          账户」中选择已保存账户，同一服务商可保存多份不同凭据；LiteSSL EAB
          与联系邮箱也在设置中维护。
        </p>
        <p class="help-note">
          「证书管理」页只展示证书列表与卡片；申请、导入和移除证书都从客户端实例的 Web 规则发起。
        </p>
      </SectionCard>

      <SectionCard title="证书移除与回退" description="移除证书后规则回到 HTTP。">
        <ul class="help-list">
          <li>
            方案 A：移除证书会删除服务器上的证书与私钥，把托管配置恢复为 HTTP，并清除规则的 HTTPS
            标记。
          </li>
          <li>方案 B：移除证书会删除隐藏 HTTPS 伴随规则与本机证书，原 HTTP 规则保持不变。</li>
          <li>移除后运行中的客户端实例会自动重载，无需手工重启。</li>
        </ul>
      </SectionCard>

      <SectionCard
        title="版本自动解析与下载任务中心"
        description="使用点自动选版，进度不再藏起来。"
      >
        <ul class="help-list">
          <li>
            安装服务端时按 SSH 探测到的服务器架构自动选 Linux
            包；创建客户端时版本号<strong>跟随所选服务器已部署版本</strong>、架构按本机。缺包会在你的操作里自动下载，不用先去版本库。
          </li>
          <li>
            版本列表随
            <code>state.json</code>
            本地持久化，<strong>启动直接回显、不自动联网</strong>；只有手动点击「获取 /
            刷新列表」才联网。页面会标明本次是「在线获取」还是「本地缓存回显」及列表更新时间。
          </li>
          <li>
            点击下载后右下角<strong>任务中心</strong>立即出现，跨页面常驻、可收起、支持多任务；显示阶段、百分比、速度与步骤，可暂停
            / 重试 / 关闭。下载不再锁死界面。
          </li>
          <li>
            支持 Range 断点续传，失败保留
            <code>.part</code>
            分片；重试次数与缓存时长可在「设置」中调整，首次离线可手动指定地址或导入完整安装包。
          </li>
        </ul>
      </SectionCard>
    </div>

    <SectionCard title="常见问题" description="点击展开查看排查思路。">
      <div class="faq">
        <details open>
          <summary>访问失败怎么排查？</summary>
          <p>
            先确认本地服务可用，再看 FRP
            是否登录成功、代理是否注册；随后检查服务器防火墙与云安全组是否放行 7000
            和实际入口端口。域名需解析到公网服务器，HTTPS 证书须匹配域名，且 TLS 终止层（系统 nginx
            或托管实例）已生效。
          </p>
        </details>
        <details>
          <summary>点了「安装服务端 / 保存实例」后在哪里看进度？</summary>
          <p>
            这是预期行为：工具先确认本机有没有对应版本与架构的安装包，没有就自动下载，下载进度在右下角任务中心。点击「安装服务端」后会先<strong>预检</strong>：端口被占用则终止并提示更换端口；发现已有
            FRP
            服务则让你选择保存只读、移除重装或取消；安装目录已有程序则询问是否覆盖上传。预览配置后，安装全过程显示在<strong>右下角进度面板</strong>（下载任务中心自动上移让位）：探测系统、上传程序（显示已传输字节）、写入配置、安装服务、自动启动，每步都有状态与时间；失败时保留具体错误原因并提供「重试」。想完全离线，可在「版本库」用「手动
            / 离线导入」提前准备。
          </p>
        </details>
        <details>
          <summary>服务器信息与自动部署</summary>
          <p>
            SSH 连接后自动读取系统版本、内核、CPU、内存和家目录磁盘信息。应用按实际运行的 systemd /
            OpenRC / SysV
            以及当前权限选择服务管理方式；条件不满足时使用后台进程。应用不会索取或保存交互 sudo
            密码。
          </p>
        </details>
        <details>
          <summary>站点检查提示 needs-review / 环境已变化？</summary>
          <p>
            站点检查会记录环境签名。当 80/443 归属、nginx
            配置或证书路径发生变化时，证书会进入「需复核」状态。请重新执行能力探测，再刷新环境并按需重新部署。
          </p>
        </details>
        <details>
          <summary>Windows 风险提示与误报</summary>
          <p>
            优先从官方 Release 下载并核对 SHA256。SmartScreen
            提示与杀毒误报应分别处理，先核对文件来源、数字签名与安全产品检测结果；确定误报后通过安全产品的单文件恢复或误报申诉入口处理。本工具不会关闭安全防护或自动添加白名单。
          </p>
        </details>
        <details>
          <summary>macOS 与 Linux</summary>
          <p>
            macOS 发布需要开发者签名及公证，以减少 Gatekeeper 提示并保持钥匙串身份稳定。Linux
            需要图形桌面、托盘支持及可用密钥环；无安全存储时凭据只在会话中保留。当前本机平台：{{
              platform || '未识别'
            }}。
          </p>
        </details>
        <details>
          <summary>旧版本与高级配置</summary>
          <p>
            v0.52.0
            之前的版本只提供原始配置入口，兼容性未全面验证。进入高级模式后不会将未知字段反向转换为表单。切换版本不自动转换配置，启动时使用选定版本校验。
          </p>
        </details>
        <details>
          <summary>卸载服务器与危险操作确认</summary>
          <p>
            删除、卸载、覆盖配置等操作统一在应用内弹出确认框，危险操作需输入确认词，确认后才向主进程下发。有部署记录时卸载会同时停止并清理远端服务及其程序、配置、日志与
            PID 文件，历史备份保留；也可只移除本机配置。
          </p>
        </details>
      </div>
    </SectionCard>
  </div>
</template>
