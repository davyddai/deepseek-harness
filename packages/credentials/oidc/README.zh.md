---
description: "可选 OIDC 浏览器认证：显式 subject 授权与可撤销连接会话。"
kind: "package-reference"
---

# OIDC 浏览器认证

[English](README.md) | 中文

## 概述

此插件实现机密客户端 Authorization Code + S256 PKCE，提供 `ctx.webAuthentication`。必须显式配置 HTTPS issuer、clientId、clientSecretEnv、精确 callbackUrls 和允许的不可变 subject。只从指定环境变量读取客户端机密。connection profile 必须注入该服务并设置 `authentication: external`；没有原生 token 回退，也不信任代理身份头。

事务使用 Secure/HttpOnly/Lax Cookie，会话使用独立 Secure/HttpOnly/Strict Cookie；state、nonce 和回调只使用一次。校验签名、issuer、audience、subject。服务端仅保存内存会话，重启失效，不持久化 ID/access token。退出要求同源 POST，撤销等待连接与在途 HTTP 清理。

## 目录

- [Profile 集成与验证](#profile-integration-and-verification)
- [本地退出](#local-logout-behavior)
- [任务所有权](#task-ownership)
- [模型体验](#model-experience)
- [已知限制与延后工作](#known-limitations-and-deferred-work)

<a id="profile-integration-and-verification"></a>
## Profile 集成与验证

`apps/cli/tests/oidc-profile.compat.spec.ts` 使用独立 HOME/workspace、临时 HTTPS issuer/CA、真实 CLI/Loader、完整页面与 WebSocket 验证。终端所有权有独立控制器测试；模拟 OIDC 与无害真实终端命令有回归测试；这些自动化测试不验证真实 IdP 或付费模型执行。

已创建终端保持 Agent 所有权，不随网页登录会话退出而关闭；已提交模型 turn、排队 prompt 与独立后台 job 不随浏览器退出取消。目前仅有同源 POST 退出端点，没有应用退出按钮。生产启用前必须评估这些边界并单独批准真实客户端配置。

<a id="local-logout-behavior"></a>
## 本地退出

退出设置主机独享的 Secure/HttpOnly/Strict 非凭据标记。自动连接恢复停留在无脚本的已退出页面，用户主动点击固定同源链接才能重新登录。退出响应到达浏览器前，携带旧会话 Cookie 的登录请求也会停留在该页。清除标记不会恢复旧会话；这不等于 Authelia 全局退出。

撤销立即销毁 HTTP 传输，协作处理器最多有一秒清理时间。不合作处理器解除传输所有权，晚到响应被丢弃；忽略取消信号的独立业务执行仍可能继续。

退出会取消当前浏览器的登录事务，包含正在交换 token 的回调，晚到结果不能创建替代会话；其他浏览器的事务不受影响。

<a id="task-ownership"></a>
## 任务所有权

仅允许一个 `allowedSubjects` 身份。必须设置绝对路径 `ownerRecordPath`，并将该记录与 DSH_HOME 任务数据一起保留；首次成功启动将配置的 issuer/sub 独占写入权限 0600 的记录。后续身份不匹配、记录损坏或不安全时拒绝启动，绝不自动改绑。不要删除该记录来接管其他身份的数据。登出及到期只撤销连接和在途请求，已接受任务及已创建终端继续归属 Agent；显式停止与资源回收不变。跨重启只恢复持久历史，不保证执行续跑。
<a id="model-experience"></a>
## 模型体验

### 浏览器认证

#### 模型可见内容

`ctx.webAuthentication` 不提供模型可见内容。

#### Token 影响

不发起模型请求，不增加模型 token。

#### KV Cache 影响

不改变模型请求前缀或保留上下文。

<a id="known-limitations-and-deferred-work"></a>
## 已知限制与延后工作

- 会话仅保存在进程内存；服务重启使会话失效。
- IdP 全局退出及账户禁用不会自动传播。绝对到期限制已签发会话的寿命，但只要 IdP 允许重新授权，就不能限制总访问时长；没有 backchannel logout 端点。
- 此插件不能替代网关保护或操作系统隔离。
- 已接受任务和已创建终端可在浏览器退出后继续；服务重启不会自动续跑执行。
- 没有应用退出按钮；已认证客户端使用同源 POST 端点。

### 开发备注

<details>
<summary>维护者的工作上下文</summary>

Backchannel logout 需要独立验证协议和重放策略；当前行为由显式配置的绝对会话寿命限定。

</details>
