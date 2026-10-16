/** Browser recovery for explicitly configured external authentication. */
import type { RpcFetch } from './rpc.ts'

/** Inputs owned by one page composition. */
export interface AuthenticationRecoveryOptions {
  /** Document-relative same-origin login route. */
  readonly loginPath: string
  /** Document-relative session probe route. */
  readonly sessionPath: string
  /** Carrier fetch, with no alternate origin or credentials. */
  readonly fetch: RpcFetch
  /** Navigate the page after the provider or outer gateway refuses the session. */
  readonly navigate: (path: string) => void
}

/**
 * Wrap calls and probe failed streams; network errors preserve normal reconnect behavior.
 * @param options - page-owned routes and carrier operations.
 * @returns wrapped fetch plus a coalesced stream-recovery probe.
 */
export function createAuthenticationRecovery(options: AuthenticationRecoveryOptions): { fetch: RpcFetch; probe: () => Promise<void> } {
  for (const path of [options.loginPath, options.sessionPath]) {
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || path.includes('?') || path.includes('#')) {
      throw new Error('connection: authentication recovery requires exact same-origin paths')
    }
  }
  let navigating = false
  let probing: Promise<void> | undefined
  const inspect = (response: Response): void => {
    if (response.status !== 401 && response.type !== 'opaqueredirect') return
    if (navigating) return
    navigating = true
    options.navigate(options.loginPath.slice(1))
  }
  return {
    fetch: async (input, init) => {
      const response = await options.fetch(input, { ...init, redirect: 'manual' })
      inspect(response)
      return response
    },
    probe() {
      if (navigating) return Promise.resolve()
      if (probing !== undefined) return probing
      probing = options.fetch(options.sessionPath.slice(1), {
        method: 'GET', credentials: 'same-origin', redirect: 'manual', cache: 'no-store',
      })
        .then(inspect).catch((error: unknown) => {
          void error /* Offline/server failures remain the controller's reconnect responsibility. */
        })
        .finally(() => { probing = undefined })
      return probing
    },
  }
}
