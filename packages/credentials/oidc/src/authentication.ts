/** HTTPS OIDC protocol and instance-owned browser sessions. */
import { createHash, randomBytes } from 'node:crypto'
import * as oidc from 'openid-client'
import type { ConnectionTrustRequest, ConnectionIndexRequest, ConnectionIndexResponse, WebAuthenticationProvider, WebAuthenticationSession } from '@deepseek-ai/dsh-client-connection'
import type { IncomingMessage } from 'node:http'

/** Explicit protocol limits and deployment identity. */
export interface Options {
  /** Exact HTTPS discovery issuer. */
  issuer: string
  /** Registered confidential client identifier. */
  clientId: string
  /** Secret resolved by the plugin from its named environment variable. */
  clientSecret: string
  /** Exact HTTPS callback URLs including the fixed callback path. */
  callbackUrls: string[]
  /** Immutable subjects allowed to act as the application owner. */
  allowedSubjects: string[]
  /** Absolute application session lifetime in seconds. */
  sessionTtlSeconds: number
  /** Single-use login transaction lifetime in seconds. */
  transactionTtlSeconds: number
  /** Maximum concurrent application sessions. */
  maxSessions: number
  /** Maximum pending browser login transactions. */
  maxTransactions: number
}
interface Transaction { state: string; nonce: string; verifier: string; callback: string; origin: string; expiresAt: number }
interface Session {
  subject: string
  origin: string
  expiresAt: number
  controller: AbortController
  timer: ReturnType<typeof setTimeout> | undefined
  id: object
  cleanups: Set<() => Promise<void>>
}
interface Reply { status: number; headers: Record<string, string | string[]>; body?: string }
type Admission = { rejection: 401 | 403 } | { principal: { kind: 'owner' }; sessionKey: string; signal: AbortSignal }
function header(headers: ConnectionTrustRequest['headers'], name: string): string | undefined {
  const value = headers instanceof Headers ? headers.get(name) : headers[name]
  return typeof value === 'string' ? value : undefined
}

const SESSION = '__Host-dsh_oidc'
const TRANSACTION = '__Host-dsh_oidc_tx'
// Non-credential marker prevents reconnect recovery from silently undoing local logout.
const LOGGED_OUT = '__Host-dsh_oidc_logged_out'
const digest = (value: string): string => createHash('sha256').update(value).digest('base64url')
const random = () => randomBytes(32).toString('base64url')
const cookie = (name: string, value: string, seconds: number, sameSite: string): string => `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${seconds}`
const response = (status: number, headers: Record<string, string | string[]> = {}): Reply => ({ status, headers: { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...headers } })

function readCookie(headers: ConnectionTrustRequest['headers'], name: string): string | undefined {
  const values = (header(headers, 'cookie') ?? '').split(';').map(x => x.trim()).filter(x => x.startsWith(name + '='))
  return values.length === 1 ? values[0]?.slice(name.length + 1) : undefined
}

function httpsUrl(value: string) {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('HTTPS URL without credentials or fragment required')
  return url
}

/**
 * Validates wire requests and owns transaction/session/connection lifetimes.
 * Protocol calls always use the platform HTTPS trust store.
 */
export class OidcAuthentication implements WebAuthenticationProvider {
  readonly loginPath = '/auth/oidc/login'
  readonly logoutPath = '/auth/oidc/logout'
  #client: oidc.Configuration
  #options: Options
  #origins: Map<string, string>
  #subjects: Set<string>
  #pending = new Map<string, Transaction>()
  #exchanging = new Map<string, { cancelled: boolean }>()
  #sessions = new Map<string, Session>()
  #loggingOut = new Set<string>()
  #draining = new Set<Promise<void>>()
  #operations = new Set<Promise<Reply>>()
  #disposed = false
  #now: () => number

  /**
   * Discover the configured HTTPS issuer with signature checks enabled.
   * @param options Explicit issuer, client, callback URLs, subject allowlist and capacity/TTL limits.
   * @returns an authentication owner, never an active application server.
   */
  static async create(options: Options): Promise<OidcAuthentication> {
    const issuer = httpsUrl(options.issuer)
    if (issuer.search) throw new Error('Issuer query forbidden')
    if (!options.clientId || !options.clientSecret) throw new Error('Client identity required')
    if (!Array.isArray(options.allowedSubjects) || options.allowedSubjects.length !== 1 || options.allowedSubjects.some(x => typeof x !== 'string' || !x)) throw new Error('Exactly one immutable owner subject required')
    for (const key of ['sessionTtlSeconds', 'transactionTtlSeconds', 'maxSessions', 'maxTransactions'] as const) {
      if (!Number.isSafeInteger(options[key]) || options[key] <= 0) throw new Error(`Positive integer ${key} required`)
    }
    if (options.sessionTtlSeconds > 86400 || options.transactionTtlSeconds > 600) throw new Error('TTL exceeds prototype limit')
    if (!Array.isArray(options.callbackUrls) || !options.callbackUrls.length) throw new Error('Callback allowlist required')
    const origins = new Map<string, string>()
    for (const raw of options.callbackUrls) {
      const url = httpsUrl(raw)
      if (url.pathname !== '/auth/oidc/callback' || url.search || origins.has(url.origin)) throw new Error('One exact callback per origin required')
      origins.set(url.origin, url.href)
    }
    const configuration = await oidc.discovery(issuer, options.clientId,
      { client_secret: options.clientSecret, id_token_signed_response_alg: 'RS256' },
      oidc.ClientSecretBasic(options.clientSecret), {
        execute: [oidc.enableNonRepudiationChecks],
        timeout: 5,
      })
    for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
      const endpoint = httpsUrl(String(configuration.serverMetadata()[field]))
      if (endpoint.origin !== issuer.origin) throw new Error('Cross-origin issuer endpoints forbidden in this prototype')
    }
    return new OidcAuthentication(configuration, options, origins, Date.now)
  }

  private constructor(configuration: oidc.Configuration, options: Options, origins: Map<string, string>, now: () => number) {
    this.#client = configuration
    this.#options = { ...options }
    this.#subjects = new Set(options.allowedSubjects)
    this.#origins = origins
    this.#now = now
  }

  #url(request: ConnectionIndexRequest, callback = false): URL | undefined {
    const host = header(request.headers, 'host')
    const path = request.url ?? '/'
    if (this.#disposed || !host) return undefined
    let url: URL
    try {
      if (path.startsWith('https://')) url = new URL(path)
      else {
        if (!path.startsWith('/') || path.startsWith('//')) return undefined
        url = new URL(path, `https://${host}`)
      }
    } catch (_error) { return undefined /* malformed wire URL is denied */ }
    if (url.host !== host || !this.#origins.has(url.origin) || url.username || url.password) return undefined
    const origin = header(request.headers, 'origin')
    if (origin !== undefined && origin !== url.origin) return undefined
    if (!callback && header(request.headers, 'sec-fetch-site') === 'cross-site') return undefined
    if (url.searchParams.has('token')) return undefined
    return url
  }

  #prune() {
    for (const [key, value] of this.#pending) if (value.expiresAt <= this.#now()) this.#pending.delete(key)
    for (const [key, value] of this.#sessions) if (value.expiresAt <= this.#now()) this.#revoke(key)
  }

  /** Start code flow; no arbitrary return URL or proxy identity is accepted.
   * @param request - exact login request from the shared WebServer.
   * @returns redirect and transaction cookie, or a credential-free rejection.
   */
  begin(request: IncomingMessage): Promise<Reply> {
    const operation = this.#begin(request)
    this.#operations.add(operation)
    void operation.then(() => this.#operations.delete(operation), () => this.#operations.delete(operation))
    return operation
  }

  async #begin(request: IncomingMessage): Promise<Reply> {
    const url = this.#url(request)
    if (!url || request.method !== 'GET' || url.pathname !== '/auth/oidc/login' || (url.search && url.search !== '?resume=1')) return response(403)
    const browserSession = readCookie(request.headers, SESSION)
    const loggingOut = browserSession !== undefined && this.#loggingOut.has(digest(browserSession))
    if ((readCookie(request.headers, LOGGED_OUT) === '1' || loggingOut) && (url.search !== '?resume=1' || loggingOut)) {
      return {
        ...response(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" }),
        body: '<!doctype html><html lang="en"><meta charset="utf-8"><title>Signed out</title><h1>Signed out</h1><p>Your application session has ended.</p><a href="/auth/oidc/login?resume=1">Sign in again</a></html>',
      }
    }
    this.#prune()
    if (this.#pending.size + this.#exchanging.size >= this.#options.maxTransactions) return response(503)
    const callback = this.#origins.get(url.origin)
    if (callback === undefined) return response(403)
    const id = random()
    const transaction = {
      state: oidc.randomState(), nonce: oidc.randomNonce(), verifier: oidc.randomPKCECodeVerifier(),
      callback, origin: url.origin,
      expiresAt: this.#now() + this.#options.transactionTtlSeconds * 1000,
    }
    const location = oidc.buildAuthorizationUrl(this.#client, {
      redirect_uri: transaction.callback, scope: 'openid', response_type: 'code',
      state: transaction.state, nonce: transaction.nonce,
      code_challenge_method: 'S256', code_challenge: await oidc.calculatePKCECodeChallenge(transaction.verifier),
    })
    if (this.#disposed || this.#pending.size + this.#exchanging.size >= this.#options.maxTransactions) return response(503)
    this.#pending.set(digest(id), transaction)
    return response(303, { location: location.href, 'set-cookie': [cookie(LOGGED_OUT, '', 0, 'Strict'), cookie(TRANSACTION, id, this.#options.transactionTtlSeconds, 'Lax')] })
  }

  /** Validate and consume one browser-bound callback, issuing an opaque revocable session.
   * @param request - exact issuer callback bound to one browser transaction.
   * @returns clean root redirect with session cookie, or a credential-free rejection.
   */
  callback(request: IncomingMessage): Promise<Reply> {
    const operation = this.#callback(request)
    this.#operations.add(operation)
    void operation.then(() => this.#operations.delete(operation), () => this.#operations.delete(operation))
    return operation
  }

  async #callback(request: IncomingMessage): Promise<Reply> {
    const url = this.#url(request, true)
    const id = readCookie(request.headers, TRANSACTION)
    if (!url || request.method !== 'GET' || url.pathname !== '/auth/oidc/callback' || !id) return response(403)
    const key = digest(id)
    const transaction = this.#pending.get(key)
    this.#pending.delete(key) // consumed before network work; duplicate callbacks cannot race
    const clear = cookie(TRANSACTION, '', 0, 'Lax')
    if (!transaction || transaction.expiresAt <= this.#now() || transaction.origin !== url.origin) return response(401, { 'set-cookie': clear })
    if (readCookie(request.headers, LOGGED_OUT) === '1') return response(401, { 'set-cookie': clear })
    if (this.#exchanging.size >= this.#options.maxTransactions) return response(503, { 'set-cookie': clear })
    const exchange = { cancelled: false }
    this.#exchanging.set(key, exchange)
    try {
      let tokens
      try {
        tokens = await oidc.authorizationCodeGrant(this.#client, url, {
          expectedState: transaction.state, expectedNonce: transaction.nonce,
          pkceCodeVerifier: transaction.verifier, idTokenExpected: true,
        })
      } catch (_error) {
        // Protocol/library errors can contain credentials; never return or log them.
        return response(401, { 'set-cookie': clear })
      }
      if (exchange.cancelled) return response(401, { 'set-cookie': clear })
      const claims = tokens.claims()
      if (!claims || !this.#subjects.has(claims.sub)) return response(403, { 'set-cookie': clear })
      this.#prune()
      if (this.#disposed || this.#sessions.size >= this.#options.maxSessions) return response(503, { 'set-cookie': clear })
      const seconds = Math.min(this.#options.sessionTtlSeconds, Math.floor(claims.exp - this.#now() / 1000))
      if (!Number.isSafeInteger(seconds) || seconds <= 0) return response(401, { 'set-cookie': clear })
      const sessionId = random()
      const sessionKey = digest(sessionId)
      const session: Session = {
        subject: claims.sub, origin: url.origin, expiresAt: this.#now() + seconds * 1000,
        controller: new AbortController(), timer: undefined, id: {}, cleanups: new Set(),
      }
      // Timer closes idle connections; request-time checks enforce expiry even if it runs late.
      session.timer = setTimeout(() => this.#revoke(sessionKey), seconds * 1000)
      session.timer.unref()
      this.#sessions.set(sessionKey, session)
      return response(303, { location: '/', 'set-cookie': [clear, cookie(SESSION, sessionId, seconds, 'Strict')] })
    } finally {
      this.#exchanging.delete(key)
    }
  }

  /** One synchronous admission for page, HTTP RPC, uploads, and WebSocket upgrade.
   * @param request - Incoming request to authorize.
   * @returns A live owner admission or an HTTP rejection status.
   */
  admit(request: ConnectionIndexRequest): Admission {
    const url = this.#url(request)
    if (!url) return { rejection: 403 }
    const raw = readCookie(request.headers, SESSION)
    if (!raw) return { rejection: 401 }
    const key = digest(raw)
    const session = this.#sessions.get(key)
    if (!session) return { rejection: 401 }
    if (session.expiresAt <= this.#now() || !this.#subjects.has(session.subject)) {
      this.#revoke(key)
      return { rejection: 401 }
    }
    if (session.origin !== url.origin) return { rejection: 401 }
    return { principal: { kind: 'owner' }, sessionKey: key, signal: session.controller.signal }
  }

  #revoke(key: string): void {
    const session = this.#sessions.get(key)
    if (!session) return
    this.#sessions.delete(key)
    clearTimeout(session.timer)
    const cleanups = [...session.cleanups]
    session.cleanups.clear()
    session.controller.abort()
    const draining = Promise.allSettled(cleanups.map(cleanup => Promise.resolve().then(cleanup))).then((results) => {
      const failure = results.find(result => result.status === 'rejected')
      if (failure?.status === 'rejected') throw new Error('OIDC session cleanup failed', { cause: failure.reason })
    })
    this.#draining.add(draining)
    // Keep rejected cleanup observable to dispose/logout, while preventing an unhandled rejection.
    void draining.then(() => this.#draining.delete(draining), () => undefined)
  }

  /** Same-origin POST logout revokes that session and awaits its attached transports.
   * @param request - browser logout request carrying its session cookie and Origin.
   * @returns a cleared cookie only after transport cleanup settles.
   */
  async logout(request: IncomingMessage): Promise<Reply> {
    const url = this.#url(request)
    if (!url || request.method !== 'POST' || url.pathname !== '/auth/oidc/logout' || header(request.headers, 'origin') !== url.origin) return response(403)
    const admission = this.admit(request)
    if ('rejection' in admission) return response(admission.rejection)
    const transactionId = readCookie(request.headers, TRANSACTION)
    if (transactionId !== undefined) {
      const transactionKey = digest(transactionId)
      this.#pending.delete(transactionKey)
      const exchange = this.#exchanging.get(transactionKey)
      if (exchange !== undefined) exchange.cancelled = true
    }
    this.#loggingOut.add(admission.sessionKey)
    this.#revoke(admission.sessionKey)
    try {
      await this.#drain()
      return response(204, { 'set-cookie': [cookie(SESSION, '', 0, 'Strict'), cookie(TRANSACTION, '', 0, 'Lax'), cookie(LOGGED_OUT, '1', 86400, 'Strict')] })
    } finally {
      this.#loggingOut.delete(admission.sessionKey)
    }
  }

  /** Admit only an opaque cookie from this provider; proxy identity headers are ignored. */
  authenticate(request: ConnectionTrustRequest) {
    const admission = this.admit(request)
    if ('rejection' in admission) return undefined
    const session = this.#sessions.get(admission.sessionKey)
    if (session === undefined) return undefined
    return { id: session.id, principal: admission.principal, signal: admission.signal }
  }

  /** Redirect a valid unauthenticated page request to the fixed login route.
   * @param request - Incoming page request.
   * @param res - Rejection or redirect response.
   * @returns Whether the caller may serve the page.
   */
  authorizeIndex(request: ConnectionIndexRequest, res: ConnectionIndexResponse): boolean {
    const admission = this.admit(request)
    if (!('rejection' in admission)) return true
    res.writeHead(admission.rejection === 403 ? 403 : 303, { 'cache-control': 'no-store', ...(admission.rejection === 401 ? { location: '/auth/oidc/login' } : {}) })
    res.end()
    return false
  }

  /** Return an allowlisted clean origin, never a reusable login credential. */
  authenticatedUrl(baseUrl: string): string {
    const url = new URL(baseUrl)
    if (!this.#origins.has(url.origin)) throw new Error('OIDC public origin is not allowlisted')
    return `${url.origin}/`
  }

  /** Register transport teardown; revocation waits for every registered owner.
   * @param authentication - Validated session whose transport is attached.
   * @param cleanup - Transport teardown awaited on revocation.
   * @returns Function unregistering this transport cleanup.
   */
  onRevoke(authentication: WebAuthenticationSession, cleanup: () => Promise<void>): () => void {
    const session = [...this.#sessions.values()].find(value => value.id === authentication.id)
    if (!session || session.controller.signal.aborted) {
      const draining = Promise.resolve().then(cleanup)
      this.#draining.add(draining)
      void draining.then(() => this.#draining.delete(draining), () => undefined)
      return () => undefined
    }
    session.cleanups.add(cleanup)
    return () => { session.cleanups.delete(cleanup) }
  }

  async #drain(): Promise<void> {
    const pending = [...this.#draining]
    const results = await Promise.allSettled(pending)
    for (const task of pending) this.#draining.delete(task)
    const failure = results.find(result => result.status === 'rejected')
    if (failure?.status === 'rejected') throw failure.reason
  }

  /** Administrative in-process revocation; this method is not a public HTTP endpoint.
   * @param subject - exact stable subject whose sessions are revoked.
   */
  async revokeSubject(subject: string): Promise<void> {
    for (const [key, session] of this.#sessions) if (session.subject === subject) this.#revoke(key)
    await this.#drain()
  }

  /** Dispose transactions, sessions and attached transports when the owning plugin unloads. */
  async dispose(): Promise<void> {
    this.#disposed = true
    this.#pending.clear()
    await Promise.allSettled([...this.#operations])
    for (const key of this.#sessions.keys()) this.#revoke(key)
    await this.#drain()
  }
}
