/** Explicit OIDC plugin; no credentials or identity are inferred from proxy headers. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import '@deepseek-ai/dsh-host-webserver'
import { bindOwner } from './owner.ts'
import { OidcAuthentication, type Options } from './authentication.ts'

/** Loader identity. */
export const name = 'credentials-oidc'
/** Exact routes require the shared WebServer. */
export const inject = ['webServer']
/** Deployment inputs; the client secret comes only from the explicitly named environment variable. */
export interface Config extends Omit<Options, 'clientSecret'> {
  /** Name of the environment variable containing this client secret. */
  clientSecretEnv: string
  /** Absolute private record pinning this task data to one issuer and subject. */
  ownerRecordPath: string
}
/** No deployment-varying authentication limit has an implicit default. */
export const Config: z<Config> = z.object({
  ownerRecordPath: z.string(), issuer: z.string(), clientId: z.string(), clientSecretEnv: z.string(),
  callbackUrls: z.array(z.string()).min(1), allowedSubjects: z.array(z.string()).min(1).max(1),
  sessionTtlSeconds: z.number().step(1).min(1).max(86400),
  transactionTtlSeconds: z.number().step(1).min(1).max(600),
  maxSessions: z.number().step(1).min(1), maxTransactions: z.number().step(1).min(1),
})

/** Mount authentication and reversible exact routes; disposal drains all admitted transport owners.
 * @param ctx - plugin scope.
 * @param config - explicit OIDC deployment configuration.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  if (!/^[A-Z][A-Z0-9_]*$/.test(config.clientSecretEnv)) throw new Error('OIDC clientSecretEnv must name one environment variable')
  const clientSecret = process.env[config.clientSecretEnv]
  if (!clientSecret) throw new Error('OIDC client secret environment variable is missing')
  const auth = await OidcAuthentication.create({ ...config, clientSecret })
  try {
    const subject = config.allowedSubjects[0]
    if (subject === undefined) throw new Error('OIDC owner subject is missing')
    await bindOwner(config.ownerRecordPath, config.issuer, subject)
  } catch (error) {
    await auth.dispose()
    throw error
  }
  ctx.effect(() => () => auth.dispose())
  ctx.provide('webAuthentication', auth)
  for (const [path, handle] of [
    ['/auth/oidc/login', auth.begin.bind(auth)],
    ['/auth/oidc/callback', auth.callback.bind(auth)],
    ['/auth/oidc/logout', auth.logout.bind(auth)],
  ] as const) {
    ctx.effect(() => ctx.webServer.register({ kind: 'exact', path, async handler(req, res) {
      const reply = await handle(req)
      res.writeHead(reply.status, reply.headers)
      res.end(reply.body)
    } }))
  }
}
