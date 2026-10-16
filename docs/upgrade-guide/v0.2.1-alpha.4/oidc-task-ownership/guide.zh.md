---
kind: upgrade-guide
description: OIDC 配置需要固定单一身份，登出后保留已提交任务。
---
# OIDC 任务所有权

[English](guide.md) | 中文

## 变更

OIDC 只接受一个 owner subject，且必须设置 `ownerRecordPath`。已创建终端在登出及认证到期后继续运行；此前会随认证会话关闭。显式停止、空闲清理和 Host 卸载仍会终止进程。服务重启不会续跑执行现场。

## 迁移

1. 设置一个已验证的 `allowedSubjects`，以及与任务数据一起保留的绝对私有路径 `ownerRecordPath`。启动固定配置中的精确 issuer/sub；不要通过删除或覆盖记录来更换所有者。
2. 确认同一身份重登可恢复原有任务和终端，其他 subject 被拒绝。
3. 要结束执行，请显式停止任务或关闭终端。登出撤销访问，后台工作仍可能使用模型额度和已授权文件。
