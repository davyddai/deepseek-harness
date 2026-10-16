/** Protocol verification uses signed mock-issuer responses through platform fetch. */
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { mountAgentLoopTestDependencies, mountAgentLoopTestHarness } from '@deepseek-ai/dsh-agent-loop-testkit'
import { createUserMessage, type GenerateOptions, type StreamChunk } from '@deepseek-ai/dsh-llm'
import type { SessionId } from '@deepseek-ai/dsh-session'
import { MockAdapter, textResponse } from '../../../core/agent-loop/tests/mock-adapter.ts'
import { Peer } from '../../../client/connection/src/peer.ts'
import { IncomingMessage } from 'node:http'
import { Socket } from 'node:net'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OidcAuthentication, type Options } from '../src/authentication.ts'

const issuer = 'https://issuer.example.test'
const origin = 'https://app.example.test'
const request = (url: string, headers: Record<string, string> = {}, method = 'GET'): IncomingMessage =>
  Object.assign(new IncomingMessage(new Socket()), { url, method, headers: { host: 'app.example.test', ...headers } })
const options: Options = {
  issuer, clientId: 'fixture-client', clientSecret: 'fixture-secret-not-real',
  callbackUrls: [origin + '/auth/oidc/callback', 'https://private.example.test/auth/oidc/callback'],
  allowedSubjects: ['stable-subject'], sessionTtlSeconds: 60, transactionTtlSeconds: 30, maxSessions: 4, maxTransactions: 4,
}
const cookie = (value: string | string[] | undefined): string => {
  if (value === undefined) throw new Error('Fixture cookie missing')
  return (typeof value === 'string' ? value : value.at(-1)!).split(';')[0]!
}
const owners: OidcAuthentication[] = []
afterEach(async () => { await Promise.all(owners.splice(0).map(owner => owner.dispose())); vi.restoreAllMocks(); vi.useRealTimers() })

async function fixture(overrides: Partial<Options> = {}) {
  const config = { ...options, ...overrides }
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const codes = new Map<string, Record<string, string>>()
  let mode = 'valid'
  const json = (value: object, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } })
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (url === issuer + '/.well-known/openid-configuration') return json({
      issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks',
      response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic'],
    })
    if (url === issuer + '/jwks') return json({ keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' }] })
    if (url !== issuer + '/token') throw new Error('Unexpected mock outbound request')
    const body = new URLSearchParams(String(init?.body))
    const code = body.get('code') ?? ''
    const saved = codes.get(code)
    codes.delete(code)
    if (!saved || saved.redirect_uri !== body.get('redirect_uri') || createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url') !== saved.code_challenge || mode === 'pkce') return json({ error: 'invalid_grant' }, 400)
    const issued = Math.floor(Date.now() / 1000)
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'fixture' })).toString('base64url')
    const claims = Buffer.from(JSON.stringify({
      iss: mode === 'issuer' ? 'https://wrong.example.test' : issuer,
      aud: mode === 'audience' ? 'wrong-client' : config.clientId,
      sub: mode === 'subject' ? 'other-subject' : 'stable-subject',
      nonce: mode === 'nonce' ? 'wrong' : saved.nonce, iat: issued,
      exp: mode === 'expired' ? issued - 120 : issued + 300,
    })).toString('base64url')
    const signingInput = header + '.' + claims
    const signature = sign('RSA-SHA256', Buffer.from(signingInput), key.privateKey).toString('base64url')
    const id_token = signingInput + '.' + (mode === 'signature' ? 'broken-signature' : signature)
    return json({ access_token: 'fixture-not-real', token_type: 'Bearer', ...(mode === 'missing-id-token' ? {} : { id_token }) })
  })
  const auth = await OidcAuthentication.create(config)
  owners.push(auth)
  const start = async () => {
    const reply = await auth.begin(request('/auth/oidc/login'))
    const location = reply.headers.location
    if (typeof location !== 'string') throw new Error('Fixture login did not redirect')
    const authorize = new URL(location)
    const code = randomUUID()
    codes.set(code, Object.fromEntries(authorize.searchParams))
    const callback = new URL(authorize.searchParams.get('redirect_uri')!)
    callback.searchParams.set('state', authorize.searchParams.get('state')!)
    callback.searchParams.set('code', code)
    return { reply, authorize, callback, transaction: cookie(reply.headers['set-cookie']) }
  }
  const finish = (flow: Awaited<ReturnType<typeof start>>) => auth.callback(request(flow.callback.pathname + flow.callback.search, { cookie: flow.transaction, 'sec-fetch-site': 'cross-site' }))
  return { auth, start, finish, setMode(value: string) { mode = value } }
}

async function signedIn(overrides: Partial<Options> = {}) {
  const fixtureValue = await fixture(overrides)
  const flow = await fixtureValue.start()
  const reply = await fixtureValue.finish(flow)
  expect(reply.status).toBe(303)
  return { ...fixtureValue, flow, reply, sessionCookie: cookie(reply.headers['set-cookie']) }
}

describe('OIDC browser provider', () => {
  it('rejects multiple owner identities before contacting an issuer', async () => {
    await expect(OidcAuthentication.create({ ...options, allowedSubjects: ['stable-subject', 'another'] })).rejects.toThrow('Exactly one')
  })

  it('uses exact callback, state, nonce, PKCE and separate Secure cookies', async () => {
    const f = await signedIn()
    expect(f.flow.authorize.searchParams.get('code_challenge_method')).toBe('S256')
    expect(f.flow.authorize.searchParams.get('state')).toBeTruthy()
    expect(f.flow.authorize.searchParams.get('nonce')).toBeTruthy()
    expect(f.flow.authorize.searchParams.get('redirect_uri')).toBe(origin + '/auth/oidc/callback')
    expect(f.flow.reply.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringContaining('Secure; HttpOnly; SameSite=Lax')]))
    expect(f.reply.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringContaining('Secure; HttpOnly; SameSite=Strict')]))
    const admission = f.auth.authenticate(request('/api/remote.mux', { cookie: f.sessionCookie }))
    expect(admission?.principal).toEqual({ kind: 'owner' })
    expect(f.auth.authenticate({ headers: new Headers({ host: 'app.example.test', cookie: f.sessionCookie }), url: origin + '/api/remote.mux' })?.id).toBe(admission?.id)
    expect(f.auth.authenticatedUrl(origin + '/?token=secret')).toBe(origin + '/')
  })

  for (const mode of ['nonce', 'issuer', 'audience', 'signature', 'expired', 'missing-id-token', 'pkce']) {
    it('rejects ' + mode + ' through real protocol validation', async () => {
      const f = await fixture(); const flow = await f.start(); f.setMode(mode)
      const reply = await f.finish(flow)
      expect(reply.status).toBe(401)
      expect(JSON.stringify(reply)).not.toContain(options.clientSecret)
    })
  }

  it('requires the exact stable subject', async () => {
    const f = await fixture(); const flow = await f.start(); f.setMode('subject')
    expect((await f.finish(flow)).status).toBe(403)
  })

  it('consumes a callback once and rejects wrong state', async () => {
    const f = await fixture(); const flow = await f.start()
    flow.callback.searchParams.set('state', 'wrong')
    expect((await f.finish(flow)).status).toBe(401)
    const second = await f.start()
    expect((await f.finish(second)).status).toBe(303)
    expect((await f.finish(second)).status).toBe(401)
  })

  it('denies forged headers, tokens, wrong Host/Origin and duplicate cookies', async () => {
    const f = await signedIn()
    for (const req of [
      request('/', { 'remote-user': 'ethan', authorization: 'Bearer forged' }),
      request('/?token=native', { cookie: f.sessionCookie }),
      request('/', { host: '127.0.0.1:3080', cookie: f.sessionCookie }),
      request('/', { origin: 'https://evil.test', cookie: f.sessionCookie }),
      request('/', { 'sec-fetch-site': 'cross-site', cookie: f.sessionCookie }),
      request('https://evil.test/', { cookie: f.sessionCookie }),
      request('https://[invalid', { cookie: f.sessionCookie }),
      request('/', { cookie: f.sessionCookie + '; ' + f.sessionCookie }),
      request('/', { host: 'private.example.test', cookie: f.sessionCookie }),
    ]) expect(f.auth.authenticate(req)).toBeUndefined()
  })

  it('same-origin POST logout aborts immediately and awaits every teardown', async () => {
    const f = await signedIn()
    const session = f.auth.authenticate(request('/', { cookie: f.sessionCookie }))!
    let release!: () => void
    const complete = new Promise<void>((resolve) => { release = resolve })
    let disposed = false
    f.auth.onRevoke(session, async () => { await complete; disposed = true })
    const logout = f.auth.logout(request('/auth/oidc/logout', { cookie: f.sessionCookie, origin }, 'POST'))
    expect(session.signal.aborted).toBe(true)
    expect(disposed).toBe(false)
    expect(f.auth.authenticate(request('/', { cookie: f.sessionCookie }))).toBeUndefined()
    // WS recovery can race the logout response before its marker cookie arrives.
    expect((await f.auth.begin(request('/auth/oidc/login', { cookie: f.sessionCookie }))).status).toBe(200)
    expect((await f.auth.begin(request('/auth/oidc/login?resume=1', { cookie: f.sessionCookie }))).status).toBe(200)
    release()
    expect((await logout).status).toBe(204)
    expect(disposed).toBe(true)
  })

  it('rejects logout CSRF and preserves the authenticated session', async () => {
    const f = await signedIn()
    for (const [headers, method] of [
      [{ cookie: f.sessionCookie, origin }, 'GET'],
      [{ cookie: f.sessionCookie }, 'POST'],
      [{ cookie: f.sessionCookie, origin: 'https://evil.test' }, 'POST'],
      [{ cookie: f.sessionCookie, origin, 'sec-fetch-site': 'cross-site' }, 'POST'],
    ] as const) {
      expect((await f.auth.logout(request('/auth/oidc/logout', headers, method))).status).toBe(403)
      expect(f.auth.authenticate(request('/', { cookie: f.sessionCookie }))).toBeDefined()
    }
  })

  it('holds automatic recovery at an inert signed-out page until explicit resume', async () => {
    const f = await signedIn()
    const reply = await f.auth.logout(request('/auth/oidc/logout', { cookie: f.sessionCookie, origin }, 'POST'))
    const marker = cookie(reply.headers['set-cookie'])
    const page = await f.auth.begin(request('/auth/oidc/login', { cookie: marker }))
    expect(page.status).toBe(200)
    expect(page.headers.location).toBeUndefined()
    expect(page.headers['content-security-policy']).toContain("default-src 'none'")
    expect(page.body).toContain('Sign in again')
    expect(f.auth.authenticate(request('/', { cookie: marker }))).toBeUndefined()
    const resume = await f.auth.begin(request('/auth/oidc/login?resume=1', { cookie: marker }))
    expect(resume.status).toBe(303)
    expect(resume.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringContaining('__Host-dsh_oidc_logged_out=;')]))
    expect((await f.auth.begin(request('/auth/oidc/login?resume=1&return=https://evil.test'))).status).toBe(403)
  })

  it('cancels only the browser transaction racing an authenticated logout', async () => {
    const f = await signedIn()
    const flow = await f.start()
    const otherBrowser = await f.start()
    const started = Promise.withResolvers<undefined>()
    const gate = Promise.withResolvers<undefined>()
    const implementation = vi.mocked(fetch).getMockImplementation()!
    vi.mocked(fetch).mockImplementation(async (input, init) => {
      if (String(input) === issuer + '/token') { started.resolve(undefined); await gate.promise }
      return implementation(input, init)
    })
    const callback = f.finish(flow)
    try {
      await started.promise
      const logout = await f.auth.logout(request('/auth/oidc/logout', {
        cookie: f.sessionCookie + '; ' + flow.transaction, origin,
      }, 'POST'))
      expect(logout.status).toBe(204)
      expect(logout.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringContaining('__Host-dsh_oidc_tx=;')]))
    } finally { gate.resolve(undefined) }
    const late = await callback
    expect(late.status).toBe(401)
    expect(JSON.stringify(late.headers['set-cookie'])).not.toContain('__Host-dsh_oidc=')
    expect((await f.finish(otherBrowser)).status).toBe(303)
  })

  it('rejects a callback carrying the signed-out marker and invalidates pending browser flow on logout', async () => {
    const f = await signedIn()
    const flow = await f.start()
    const marker = '__Host-dsh_oidc_logged_out=1'
    expect((await f.auth.callback(request(flow.callback.pathname + flow.callback.search, {
      cookie: flow.transaction + '; ' + marker,
    }))).status).toBe(401)
    const pending = await f.start()
    await f.auth.logout(request('/auth/oidc/logout', { cookie: f.sessionCookie + '; ' + pending.transaction, origin }, 'POST'))
    expect((await f.finish(pending)).status).toBe(401)
    const resume = await f.auth.begin(request('/auth/oidc/login?resume=1', { cookie: marker }))
    expect(resume.status).toBe(303)
    expect(resume.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringContaining('__Host-dsh_oidc_logged_out=;')]))
  })

  it('provider unload revokes sessions and drains connection cleanup', async () => {
    const f = await signedIn()
    const session = f.auth.authenticate(request('/', { cookie: f.sessionCookie }))!
    let closed = false
    f.auth.onRevoke(session, async () => { closed = true })
    await f.auth.dispose()
    expect(closed).toBe(true)
    expect(session.signal.aborted).toBe(true)
    expect((await f.auth.begin(request('/auth/oidc/login'))).status).toBe(403)
  })
  it('expires idle sessions and awaits administrative revocation', async () => {
    vi.useFakeTimers()
    const f = await signedIn({ sessionTtlSeconds: 1 })
    const session = f.auth.authenticate(request('/', { cookie: f.sessionCookie }))!
    let closed = 0
    f.auth.onRevoke(session, async () => { closed++ })
    await vi.advanceTimersByTimeAsync(1001)
    expect(session.signal.aborted).toBe(true)
    expect(closed).toBe(1)
    expect(f.auth.authenticate(request('/', { cookie: f.sessionCookie }))).toBeUndefined()
    const next = await f.start(); const reply = await f.finish(next)
    const replacement = f.auth.authenticate(request('/', { cookie: cookie(reply.headers['set-cookie']) }))!
    f.auth.onRevoke(replacement, async () => { closed++ })
    await f.auth.revokeSubject('stable-subject')
    expect(replacement.signal.aborted).toBe(true)
    expect(closed).toBe(2)
  })

  it('bounds transaction and session storage and rejects expired callbacks', async () => {
    vi.useFakeTimers()
    const f = await fixture({ maxTransactions: 1, maxSessions: 1, transactionTtlSeconds: 1 })
    const first = await f.start()
    expect((await f.auth.begin(request('/auth/oidc/login'))).status).toBe(503)
    await vi.advanceTimersByTimeAsync(1001)
    expect((await f.finish(first)).status).toBe(401)
    const second = await f.start()
    expect((await f.finish(second)).status).toBe(303)
    const third = await f.start()
    expect((await f.finish(third)).status).toBe(503)
  })

  it('captures every cleanup before abort listeners unregister them', async () => {
    const f = await signedIn()
    const session = f.auth.authenticate(request('/', { cookie: f.sessionCookie }))!
    let completed = false
    const release = f.auth.onRevoke(session, async () => { completed = true })
    session.signal.addEventListener('abort', release, { once: true })
    await f.auth.revokeSubject('stable-subject')
    expect(completed).toBe(true)
  })

  it('contains one failing cleanup and still awaits the other owners', async () => {
    const f = await signedIn()
    const session = f.auth.authenticate(request('/', { cookie: f.sessionCookie }))!
    let completed = false
    f.auth.onRevoke(session, async () => { throw new Error('fixture cleanup failure') })
    f.auth.onRevoke(session, async () => { completed = true })
    await expect(f.auth.revokeSubject('stable-subject')).rejects.toThrow('OIDC session cleanup failed')
    expect(completed).toBe(true)
    expect(session.signal.aborted).toBe(true)
  })

})


it.each(['page-close', 'network-disconnect', 'expiry', 'logout'] as const)('keeps an accepted model turn across %s and restores its result after the same identity logs in', async (cause) => {
  const f = await signedIn({ sessionTtlSeconds: 1 })
  const session = f.auth.authenticate(request('/api', { cookie: f.sessionCookie }))!
  const ctx = new Context()
  const started = Promise.withResolvers<undefined>()
  const finish = Promise.withResolvers<undefined>()
  class DeferredModel extends MockAdapter {
    override async * stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
      started.resolve(undefined)
      await finish.promise
      options.signal?.throwIfAborted()
      yield * super.stream(options)
    }
  }
  try {
    await mountAgentLoopTestDependencies(ctx)
    const harness = await mountAgentLoopTestHarness(ctx)
    const adapter = new DeferredModel([textResponse('background completed')])
    ctx.llm.registerAdapter(['mock'], adapter)
    const agent = await harness.create('background-owned-task' as SessionId, { provider: 'mock', model: 'mock' })
    const peer = new Peer(ctx, { principal: session.principal })
    f.auth.onRevoke(session, () => peer.dispose())
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'run in background' }], source: { kind: 'user' } }))
    await started.promise
    if (cause === 'logout') await f.auth.logout(request('/auth/oidc/logout', { cookie: f.sessionCookie, origin }, 'POST'))
    else if (cause === 'expiry') await new Promise(resolve => setTimeout(resolve, 1100))
    else await peer.dispose()
    expect(agent.status).toBe('running')
    finish.resolve(undefined)
    await agent.whenIdle()
    expect(JSON.stringify(agent.session.snapshotEvents())).toContain('background completed')
    const next = await f.start()
    const reply = await f.finish(next)
    expect(reply.status).toBe(303)
    expect(f.auth.authenticate(request('/api', { cookie: cookie(reply.headers['set-cookie']) }))).toBeDefined()
    expect(ctx.agents.get(agent.id)).toBe(agent)
    f.setMode('subject')
    const stranger = await f.start()
    expect((await f.finish(stranger)).status).toBe(403)
    expect(f.auth.authenticate(request('/api'))).toBeUndefined()
    expect(JSON.stringify(agent.session.snapshotEvents())).toContain('background completed')
  } finally { finish.resolve(undefined); await ctx.fiber.dispose() }
})


it('keeps explicit task cancellation available after the browser owner leaves', async () => {
  const ctx = new Context()
  try {
    await mountAgentLoopTestDependencies(ctx)
    const harness = await mountAgentLoopTestHarness(ctx)
    const model = new MockAdapter(['hang'])
    ctx.llm.registerAdapter(['mock'], model)
    const agent = await harness.create('explicit-stop-task' as SessionId, { provider: 'mock', model: 'mock' })
    const peer = new Peer(ctx, { principal: { kind: 'owner' } })
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'wait for explicit stop' }], source: { kind: 'user' } }))
    await expect.poll(() => model.requests.length).toBe(1)
    await peer.dispose()
    expect(agent.status).toBe('running')
    agent.cancel({ kind: 'user' })
    await agent.whenIdle()
    expect(agent.status).toBe('idle')
    expect(model.requests[0]!.signal?.aborted).toBe(true)
  } finally { await ctx.fiber.dispose() }
})
