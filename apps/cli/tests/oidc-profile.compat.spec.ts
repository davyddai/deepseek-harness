/** The production CLI/Loader/Web bundle, using only disposable state and an HTTPS test issuer. */
import { generateKeyPairSync, createHash, randomUUID, sign } from 'node:crypto'
import { createServer } from 'node:https'
import { request } from 'node:http'
import { once } from 'node:events'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { execa } from 'execa'
import { it, expect } from 'vitest'
import WebSocket from 'ws'
import { materializeTlsFixture } from '../../../packages/host/webserver/tests/tls-fixture.ts'
const root = fileURLToPath(new URL('../../../', import.meta.url))
const origin = 'https://harness.fixture.test'
const cookieOf = (headers: Record<string, string | string[] | undefined>) => { const v = headers['set-cookie']; return (Array.isArray(v) ? v.at(-1)! : v!).split(';')[0]! }

it('runs OIDC through the actual Web profile, protecting HTML/API and closing admitted WebSockets', { timeout: 150_000 }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'dsh-oidc-profile-'))
  const home = join(temporary, 'home')
  await mkdir(join(temporary, 'workspace'))
  const tls = await materializeTlsFixture(join(temporary, 'tls'))
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' }
  const codes = new Map<string, Record<string, string>>()
  let issuer = ''; let mode = 'valid'; let tokenRequests = 0; let clientMatched = false; let pkceMatched = false
  const idp = createServer({ cert: await readFile(tls.certFile), key: await readFile(tls.keyFile) }, async (req, res) => {
    const json = (body: unknown, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
    if (req.url === '/.well-known/openid-configuration') return json({ issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks', response_types_supported: ['code'], grant_types_supported: ['authorization_code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic'] })
    if (req.url === '/jwks') return json({ keys: [jwk] })
    if (req.url !== '/token') return json({}, 404)
    let raw = ''; for await (const chunk of req) raw += String(chunk)
    tokenRequests++; const credentials = Buffer.from(req.headers.authorization?.split(' ')[1] ?? '', 'base64').toString().split(':').map(decodeURIComponent); clientMatched = req.headers.authorization?.startsWith('Basic ') === true && credentials[0] === 'fixture-client' && credentials[1] === 'fixture-not-real'; const body = new URLSearchParams(raw); const saved = codes.get(body.get('code') ?? ''); codes.delete(body.get('code') ?? '')
    pkceMatched = !!saved && createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url') === saved.code_challenge; if (mode === 'pkce' || !clientMatched || !saved || body.get('redirect_uri') !== saved.redirect_uri || createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url') !== saved.code_challenge) return json({ error: 'invalid_grant' }, 400)
    const now = Math.floor(Date.now() / 1000); const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')
    const unsigned = enc({ alg: 'RS256', kid: 'fixture' }) + '.' + enc({ iss: mode === 'issuer' ? issuer + '/wrong' : issuer, sub: mode === 'subject' ? 'other-user' : 'fixture-ethan', aud: mode === 'audience' ? 'other-client' : 'fixture-client', nonce: mode === 'nonce' ? 'wrong' : saved.nonce, iat: now, exp: now + 60 })
    return json({ access_token: 'test-only', token_type: 'Bearer', expires_in: 60, id_token: unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url') })
  })
  idp.listen(0, '127.0.0.1'); await once(idp, 'listening'); issuer = `https://127.0.0.1:${(idp.address() as { port: number }).port}`
  const profile = join(home, 'profiles', 'web'); await mkdir(profile, { recursive: true })
  await writeFile(join(profile, 'package.json'), JSON.stringify({ name: 'oidc-test-profile', private: true, dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } } }))
  const probe = join(temporary, 'probe.mjs')
  await writeFile(probe, 'export const name=\'oidc-probe\'; export const inject=[\'webServer\',\'connection\']; export function apply(ctx) { console.log(\'OIDC_TEST_PORT=\'+ctx.webServer.port); ctx.connection.fetch.register({path:\'/api/fixture-wait\',methods:[\'GET\'],requestBody:\'buffered\',async fetch(req){console.log(\'OIDC_TEST_WAIT\');await new Promise(resolve=>req.signal.addEventListener(\'abort\',resolve,{once:true}));console.log(\'OIDC_TEST_ABORT\');return new Response(\'cancelled\');}}); }')
  await writeFile(join(profile, 'cordis.patch.yml'), JSON.stringify([
    { id: 'session-telemetry-otel', disabled: true },
    { id: 'web-runtime', config: { openBrowser: false, printUrl: true, publicUrl: origin, surfaceContext: false } },
    { id: 'connection', inject: ['webStartup', 'webAuthentication'], config: { authentication: 'external', trustedHosts: ['harness.fixture.test'] } },
    { insert: [ { id: 'oidc', name: join(root, 'packages/credentials/oidc/src/index.ts'), config: { ownerRecordPath: join(home, 'oidc-owner.json'), issuer, clientId: 'fixture-client', clientSecretEnv: 'OIDC_PROFILE_TEST_SECRET', callbackUrls: [origin + '/auth/oidc/callback'], allowedSubjects: ['fixture-ethan'], sessionTtlSeconds: 5, transactionTtlSeconds: 30, maxSessions: 10, maxTransactions: 10 } }, { id: 'oidc-probe', name: probe } ] },
  ]))
  const child = execa(process.execPath, ['--import', join(root, 'node_modules/tsx/dist/esm/index.mjs'), join(root, 'apps/cli/src/bin.ts'), 'web', '--no-open', '--port', '0'], { cwd: join(temporary, 'workspace'), extendEnv: false, env: { PATH: process.env.PATH, TSX_TSCONFIG_PATH: join(root, 'tsconfig.base.json'), HOME: temporary, TMPDIR: tmpdir(), DSH_HOME: home, NODE_EXTRA_CA_CERTS: tls.caFile, OIDC_PROFILE_TEST_SECRET: 'fixture-not-real', DSH_TELEMETRY_DISABLED: '1' }, reject: false, timeout: 120_000 })
  let exited = false; void child.then(() => { exited = true }); let output = ''; child.stdout?.on('data', (c) => { output += String(c) }); child.stderr?.on('data', (c) => { output += String(c) })
  try {
    const deadline = Date.now() + 90_000
    while (!(/OIDC_TEST_PORT=(\d+)/.test(output) && output.includes('dsh web:'))) { if (exited || Date.now() > deadline) throw new Error('Profile readiness: ' + output.replace(/https?:\/\/[^\s]+/g, '[URL redacted]').slice(0, 6000)); await new Promise(r => setTimeout(r, 50)) }
    const port = Number(/OIDC_TEST_PORT=(\d+)/.exec(output)![1])
    const wire = (path: string, headers: Record<string, string> = {}, method = 'GET') => new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port, path, method, headers: { host: 'harness.fixture.test', ...headers } }, (res) => { let text = ''; res.on('data', (c) => { text += String(c) }); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: text })) }); req.on('error', reject); req.end()
    })
    expect((await wire('/api')).status).toBe(401)
    expect((await wire('/auth/session')).status).toBe(401)
    expect((await wire('/api', { 'remote-user': 'ethan', 'authorization': 'Bearer fixture-token' })).status).toBe(401)
    expect((await wire('/', { host: 'evil.test' })).status).toBe(403)
    expect((await wire('/api', { origin: 'https://evil.test' })).status).toBe(403)
    expect((await wire('/connect?token=fixture-token')).status).toBe(401)
    expect((await wire('/api', { host: '127.0.0.1' })).status).toBe(401)
    const deniedSocket = (headers: Record<string, string>) => new Promise<number>((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${port}/api/remote.mux`, { headers: { host: 'harness.fixture.test', ...headers } }); socket.on('error', () => {}); socket.on('open', () => { socket.terminate(); reject(new Error('Unauthenticated WebSocket admitted')) }); socket.on('unexpected-response', (_req, res) => { res.resume(); socket.terminate(); resolve(res.statusCode!) })
    })
    expect(await deniedSocket({ origin })).toBe(401)
    expect(await deniedSocket({ origin: 'https://evil.test' })).toBe(403)
    const index = await wire('/'); expect(index.status).toBe(303); expect(index.headers.location).toBe('/auth/oidc/login')
    const flow = async () => {
      const login = await wire('/auth/oidc/login'); expect(login.status).toBe(303)
      const authorize = new URL(String(login.headers.location)); expect(authorize.searchParams.get('code_challenge_method')).toBe('S256')
      const code = randomUUID(); codes.set(code, Object.fromEntries(authorize.searchParams))
      const callback = new URL(authorize.searchParams.get('redirect_uri')!); callback.searchParams.set('code', code); callback.searchParams.set('state', authorize.searchParams.get('state')!)
      return { callback: callback.pathname + callback.search, tx: cookieOf(login.headers) }
    }
    for (const failure of ['subject', 'nonce', 'issuer', 'audience', 'pkce']) { mode = failure; const f = await flow(); expect((await wire(f.callback, { cookie: f.tx })).status, `${failure}: tokenRequests=${tokenRequests} clientMatched=${clientMatched} pkceMatched=${pkceMatched}`).toBe(failure === 'subject' ? 403 : 401) }
    mode = 'valid'; const tampered = await flow(); expect((await wire(tampered.callback.replace(/state=[^&]+/, 'state=wrong'), { cookie: tampered.tx })).status).toBe(401); const f = await flow(); const accepted = await wire(f.callback, { cookie: f.tx }); expect(accepted.status).toBe(303)
    const cookie = cookieOf(accepted.headers); expect(String(accepted.headers['set-cookie'])).toContain('Secure')
    expect((await wire(f.callback, { cookie: f.tx })).status).toBe(401)
    const html = await wire('/', { cookie }); expect(html.status).toBe(200); expect(html.body).toContain('<html'); expect(html.body).toContain('__DSH_AUTHENTICATION__'); expect(html.body).toContain('/auth/oidc/login'); expect((await wire('/auth/session', { cookie })).status).toBe(204)
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/remote.mux`, { headers: { host: 'harness.fixture.test', origin, cookie } }); await once(ws, 'open'); const closed = once(ws, 'close')
    const pending = wire('/api/fixture-wait', { cookie }).catch(() => undefined)
    while (!output.includes('OIDC_TEST_WAIT')) { await new Promise(r => setTimeout(r, 25)) }
    for (const [headers, method] of [[{ cookie, origin }, 'GET'], [{ cookie }, 'POST'], [{ cookie, origin: 'https://evil.test' }, 'POST']] as const) expect((await wire('/auth/oidc/logout', headers, method)).status).toBe(403)
    const logout = await wire('/auth/oidc/logout', { cookie, origin }, 'POST'); expect(logout.status).toBe(204)
    const loggedOutCookie = cookieOf(logout.headers); const landing = await wire('/auth/oidc/login', { cookie: loggedOutCookie }); expect(landing.status).toBe(200); expect(landing.headers.location).toBeUndefined(); expect(landing.body).toContain('Sign in again'); expect((await wire('/auth/oidc/login?resume=1', { cookie: loggedOutCookie })).status).toBe(303); await closed; await pending; expect(output).toContain('OIDC_TEST_ABORT'); expect((await wire('/api', { cookie })).status).toBe(401); expect((await wire('/auth/session', { cookie })).status).toBe(401)
    const exp = await flow(); const expCookie = cookieOf((await wire(exp.callback, { cookie: exp.tx })).headers)
    const expWs = new WebSocket(`ws://127.0.0.1:${port}/api/remote.mux`, { headers: { host: 'harness.fixture.test', origin, cookie: expCookie } }); await once(expWs, 'open'); await once(expWs, 'close')
    expect((await wire('/api', { cookie: expCookie })).status).toBe(401)
  } finally { child.kill('SIGTERM'); await child; idp.closeAllConnections(); await new Promise<void>(resolve => idp.close(() => resolve())); await rm(temporary, { recursive: true, force: true }) }
})
