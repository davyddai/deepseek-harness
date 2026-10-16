/** External session recovery preserves offline retries and uses same-origin login paths. */
import { describe, expect, it, vi } from 'vitest'
import { createAuthenticationRecovery } from '../src/client/authentication-recovery.ts'

describe('external authentication recovery', () => {
  it('redirects once after HTTP 401 and leaves the error response to its caller', async () => {
    const navigate = vi.fn()
    const send = vi.fn(async () => new Response(null, { status: 401 }))
    const recovery = createAuthenticationRecovery({ loginPath: '/auth/oidc/login', sessionPath: '/auth/session', fetch: send, navigate })
    expect((await recovery.fetch('api/fixture', { method: 'POST' })).status).toBe(401)
    await recovery.fetch('api/fixture', { method: 'POST' })
    expect(navigate).toHaveBeenCalledExactlyOnceWith('auth/oidc/login')
    expect(send).toHaveBeenCalledWith('api/fixture', { method: 'POST', redirect: 'manual' })
  })

  it('coalesces simultaneous stream probes and recovers after an outer gateway redirect', async () => {
    const navigate = vi.fn()
    const response = Promise.withResolvers<Response>()
    const send = vi.fn(() => response.promise)
    const recovery = createAuthenticationRecovery({ loginPath: '/auth/oidc/login', sessionPath: '/auth/session', fetch: send, navigate })
    const first = recovery.probe()
    expect(recovery.probe()).toBe(first)
    const opaque = new Response(null)
    Object.defineProperty(opaque, 'type', { value: 'opaqueredirect' })
    response.resolve(opaque)
    await first
    expect(navigate).toHaveBeenCalledExactlyOnceWith('auth/oidc/login')
    expect(send).toHaveBeenCalledOnce()
  })

  it('does not navigate for offline errors, normal sessions or authorization denials', async () => {
    const navigate = vi.fn()
    const send = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(new Response(null, { status: 204 })).mockResolvedValueOnce(new Response(null, { status: 403 }))
    const recovery = createAuthenticationRecovery({ loginPath: '/auth/oidc/login', sessionPath: '/auth/session', fetch: send, navigate })
    await recovery.probe()
    await recovery.probe()
    await recovery.probe()
    expect(navigate).not.toHaveBeenCalled()
  })

  it('rejects alternate origins and path traversal expressed through a backslash', () => {
    for (const loginPath of ['https://evil.test/', '//evil.test/', '/\\evil.test/', '/auth/login?next=evil', '/auth/login#evil']) {
      expect(() => createAuthenticationRecovery({ loginPath, sessionPath: '/auth/session', fetch: vi.fn(), navigate: vi.fn() })).toThrow('same-origin')
    }
  })
})
