---
description: "Opt-in OIDC browser authentication with explicit subject authorization and revocable connection sessions."
kind: "package-reference"
---

# OIDC browser authentication

English | [中文](README.zh.md)

## Summary

Use OIDC Authorization Code + PKCE to protect the Web application. Exact HTTPS callback origins and immutable subject identifiers must be explicitly allowlisted. All API and WebSocket consumers use opaque, memory-only sessions and receive revocation cancellation. Neither proxy identity headers nor native startup tokens authenticate this provider.

## Table of Contents

- [Profile integration and verification](#profile-integration-and-verification)
- [Local logout behavior](#local-logout-behavior)
- [Task ownership](#task-ownership)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)

## Profile integration and verification

Client credentials are read only from the explicitly configured environment variable. Login transactions use a Secure HttpOnly Lax cookie; application sessions use a separate Secure HttpOnly Strict cookie. Transactions are single-use. Discovery and code exchange require HTTPS and RS256 signature verification; issuer endpoints must remain on the configured issuer origin. Local logout requires a same-origin POST and waits for transport cleanup. Provider unload aborts and drains all admitted owners.

Mount this package before a connection plugin configured with `authentication: external`; explicitly inject `webAuthentication` in that connection profile row. Required settings are `issuer`, `clientId`, `clientSecretEnv`, `callbackUrls` `allowedSubjects`, `ownerRecordPath`, explicit session/transaction TTLs and capacity limits. Only the named environment variable is read. Callbacks must be exact HTTPS `/auth/oidc/callback` URLs. Authorize verified immutable `sub` values, not assumed usernames. See `apps/cli/tests/oidc-profile.compat.spec.ts` for a complete isolated Loader profile.

The repeatable full-profile test uses a temporary HTTPS OIDC issuer, signed tokens, temporary CA and separate child-process home/workspace. It verifies built HTML, login recovery configuration, protocol negatives, native-token rejection, real gateway WebSockets, logout/expiry closure and in-flight HTTP cancellation. It makes no model call. Terminal ownership has controller tests including an inert real PTY command after authentication revocation; these automated tests do not validate a live issuer or paid-model execution.

Local logout does not cancel already submitted model turns, queued prompts or independently owned background jobs. No application logout button is added yet; use the same-origin POST endpoint from an authenticated client. Operators must review real issuer configuration and these operational limits before enabling the profile.

## Local logout behavior

Logout also sets a host-only Secure/HttpOnly/Strict non-credential marker. Automatic reconnect recovery stops at a script-free signed-out page rather than silently starting OIDC again. The fixed same-origin “Sign in again” link resumes login explicitly. A request carrying the old session cookie is held at the same page while logout cleanup is pending, before the marker response reaches the browser. Clearing browser cookies removes this convenience marker; it does not revive a revoked session. This is local application logout, not Authelia global logout.

HTTP transports close immediately on revocation. Cooperative handlers are given up to one second to clean up; uncooperative work is detached from the transport, with late responses discarded. Ignoring an AbortSignal can still leave independent business execution running.

Logout cancels the current browser transaction, including token exchanges already in flight; a late callback cannot mint a replacement session. Other browser transactions are not revoked.

## Task ownership

Only one `allowedSubjects` identity is supported. Set an absolute `ownerRecordPath` and retain that record with the DSH_HOME task data. Initial successful activation exclusively publishes the configured issuer/sub in a mode-0600 record. Later mismatches, malformed or unsafe records fail startup without rebinding. Never delete the record to take over another identity’s data. Logout and expiry revoke transports and in-flight requests; accepted tasks and committed terminals remain Agent-owned. Explicit stop and resource reclamation remain available. Persisted history survives restart; running execution does not automatically resume.
## Model Experience

### Browser authentication

#### What the model sees

`ctx.webAuthentication` supplies no model-visible content. Its identity decisions authorize browser transport admission only.

#### Token effect

Authentication adds zero model tokens and makes no model requests.

#### KV Cache effect

Authentication does not modify model-request prefixes or retained context, so it does not invalidate an otherwise reusable model prefix.

## Known Limitations and Deferred Work

- Session storage is process-local; restart invalidates sessions.
- IdP global logout and account disable do not propagate automatically. Absolute expiry bounds an issued application session, but does not bound total access while the IdP still permits fresh authorization. There is no backchannel logout endpoint.
- This plugin does not replace gateway protection or operating-system confinement.
- Accepted tasks and committed terminals continue after browser logout; running execution does not resume automatically after a service restart.
- There is no application logout button; authenticated clients use the same-origin POST endpoint.

### Dev Note

<details>
<summary>Working context for maintainers</summary>

Backchannel logout requires a separately verified protocol and replay policy. Current behavior is defined by the explicit absolute session TTL.

</details>
