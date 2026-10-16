---
kind: upgrade-guide
description: OIDC profiles require a pinned single operator and retain committed tasks after logout.
---
# OIDC task ownership

English | [中文](guide.zh.md)

## Change

OIDC profiles accept one owner subject and require `ownerRecordPath`. Committed terminals survive logout and authentication expiry; previously session-created terminals closed. Explicit stop, idle cleanup and Host disposal still terminate processes. Service restart does not resume execution.

## Migration

1. Configure one verified `allowedSubjects` value and an absolute private `ownerRecordPath` retained alongside the task data. Startup pins the exact configured issuer/sub; do not delete or overwrite this record to change owners.
2. Confirm the same identity can log in again and recover the existing task and terminal. Confirm other subjects are rejected.
3. Use explicit task stop or terminal close when execution must end. Logout revokes access while background work may continue using model quota and authorized files.
