/**
 * node:http ↔ WHATWG fetch bridge for the /api transport (host side of the
 * web carrier; the fetch-shaped handler itself is transport-agnostic).
 */

import type { IncomingMessage } from 'node:http'
import type { PeerScope } from '@deepseek-ai/dsh-typert-protocol'
import { Readable } from 'node:stream'
import type { ConnectionFetchHandler } from './rpc.ts'

/** Default carrier cap for all HTTP RPC bodies: sized for the default
 * aggregate image limit (200 MiB) after base64 expansion plus envelope
 * headroom (~267.7 MiB required), rounded up for slack. The bridge buffers
 * each body in memory, so this cap is also the per-request resident bound. */
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 300 * 1024 * 1024

interface BridgeServerResponse {
  readonly destroyed: boolean
  readonly writableEnded: boolean
  destroy?(): unknown
  on(event: 'close', listener: () => void): this
  off(event: 'close' | 'drain', listener: () => void): this
  once(event: 'close' | 'drain', listener: () => void): this
  writeHead(statusCode: number, headers?: Record<string, string>): unknown
  write(chunk: Uint8Array): boolean
  end(): unknown
}

/**
 * Bridge one node:http request to the fetch-shaped handler (client close
 * aborts; response writes respect backpressure and stop on disconnect).
 * @param req - incoming node:http request.
 * @param res - node:http response the bridge writes and owns to completion.
 * @param apiHandler - fetch-shaped API carrier the request is dispatched to.
 * @param peer - Peer the carrier admitted the request as.
 * @param maxRequestBodyBytes - maximum bytes buffered for a buffered route.
 * @param lifetimeSignal - optional external-session cancellation; absent preserves native request lifetime.
 */
export async function bridge(
  req: IncomingMessage,
  res: BridgeServerResponse,
  apiHandler: ConnectionFetchHandler,
  peer: PeerScope,
  maxRequestBodyBytes = DEFAULT_MAX_REQUEST_BODY_BYTES,
  lifetimeSignal?: AbortSignal,
): Promise<void> {
  if (lifetimeSignal === undefined) {
    await bridgeRequest(req, res, apiHandler, peer, maxRequestBodyBytes)
    return
  }
  const cancelled = new AbortController()
  const signal = AbortSignal.any([lifetimeSignal, cancelled.signal])
  const settled = Promise.withResolvers<void>()
  let completed = false
  const detached = Promise.withResolvers<void>()
  // Security limit: revocation cannot wait indefinitely for an uncooperative handler.
  // Detaching transport ownership does not stop independent business execution.
  const terminate = (): void => {
    res.destroy?.()
    req.destroy()
  }
  signal.addEventListener('abort', terminate, { once: true })
  if (signal.aborted) terminate()
  const release = peer.ctx.effect(() => async () => {
    if (completed) return
    cancelled.abort(new Error('Authentication session revoked'))
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([settled.promise, new Promise<void>((resolve) => {
        timer = setTimeout(() => { detached.resolve(); resolve() }, 1000)
      })])
    } finally {
      clearTimeout(timer)
    }
  }, 'client-connection: external request lifetime')
  const operation = bridgeRequest(req, res, apiHandler, peer, maxRequestBodyBytes, signal)
    .catch((error: unknown) => { if (!signal.aborted) throw error })
    .finally(() => { completed = true; settled.resolve() })
  try {
    await Promise.race([operation, detached.promise])
  } finally {
    await release()
    signal.removeEventListener('abort', terminate)
  }
}

async function bridgeRequest(
  req: IncomingMessage,
  res: BridgeServerResponse,
  apiHandler: ConnectionFetchHandler,
  peer: PeerScope,
  maxRequestBodyBytes: number,
  lifetimeSignal?: AbortSignal,
): Promise<void> {
  const abort = new AbortController()
  const signal = lifetimeSignal === undefined ? abort.signal : AbortSignal.any([abort.signal, lifetimeSignal])
  // Client-disconnect detection MUST hang off the response, not the request:
  // since Node 16, IncomingMessage 'close' fires as soon as the request body is
  // fully consumed (immediately for a bodyless GET), which would abort a
  // streaming response right after open. ServerResponse 'close' fires on connection teardown;
  // writableEnded distinguishes a normal end() from the client going away.
  res.on('close', () => {
    if (!res.writableEnded) abort.abort()
  })
  /* v8 ignore next 2 -- node:http always sets url/method on server requests. */
  const url = new URL(req.url ?? '/', 'http://dsh.internal')
  const method = req.method ?? 'GET'
  const headers = Object.fromEntries(
    Object.entries(req.headers).filter(([, value]) => typeof value === 'string') as [string, string][],
  )
  const bodyMode = apiHandler.requestBodyMode({ method, url })
  let request: Request
  if (bodyMode === 'buffered') {
    const declaredLength = req.headers['content-length']
    if (declaredLength !== undefined && Number(declaredLength) > maxRequestBodyBytes) {
      res.writeHead(413, { connection: 'close' })
      res.end()
      req.destroy()
      return
    }
    const chunks: Buffer[] = []
    let received = 0
    for await (const chunk of req) {
      const buffer = chunk as Buffer
      received += buffer.byteLength
      if (received > maxRequestBodyBytes) {
        res.writeHead(413, { connection: 'close' })
        res.end()
        req.destroy()
        return
      }
      chunks.push(buffer)
    }
    request = new Request(url, {
      method,
      headers,
      ...chunks.length > 0 ? { body: Buffer.concat(chunks) } : {},
      signal,
    })
  } else {
    request = new Request(url, {
      method,
      headers,
      body: Readable.toWeb(req) as ReadableStream<Uint8Array>,
      signal,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' })
  }
  const response = await apiHandler.fetch(request, peer)
  if (lifetimeSignal?.aborted) {
    // A handler may settle after transport cleanup has already detached it.
    void response.body?.cancel().catch((error: unknown) => { void error /* The revoked transport owns no further response bytes. */ })
    return
  }
  const requestUnread = bodyMode === 'streaming' && !req.readableEnded
  const responseHeaders = Object.fromEntries(response.headers.entries())
  res.writeHead(response.status, requestUnread ? { ...responseHeaders, connection: 'close' } : responseHeaders)
  if (response.body === null) {
    res.end()
    if (requestUnread) req.destroy()
    return
  }
  for await (const chunk of lifetimeSignal === undefined ? response.body : revocableBody(response.body, signal)) {
    // Drain without writing after disconnect: cancelling Node multipart bodies
    // can race their producer and reject with ERR_INVALID_STATE.
    if (signal.aborted) continue
    // Backpressure: a false return means the socket buffer is full — wait for drain
    // instead of buffering unboundedly (slow or suspended consumers). 'close' also
    // resolves so a mid-wait disconnect cannot park this loop forever.
    if (!res.write(chunk) && !res.destroyed) {
      await new Promise<void>((resolve) => {
        const done = (): void => {
          res.off('drain', done)
          res.off('close', done)
          resolve()
        }
        res.once('drain', done)
        res.once('close', done)
      })
    }
  }
  if (!lifetimeSignal?.aborted) res.end()
  if (requestUnread) req.destroy()
}

/** Cancel the owned response reader when an external session is revoked. */
async function* revocableBody(body: ReadableStream<Uint8Array>, signal: AbortSignal): AsyncGenerator<Uint8Array> {
  const reader = body.getReader()
  const cancel = (): void => {
    void reader.cancel(signal.reason).catch((error: unknown) => { void error /* Cleanup is bounded by the transport owner. */ })
  }
  signal.addEventListener('abort', cancel, { once: true })
  try {
    if (signal.aborted) cancel()
    while (!signal.aborted) {
      const next = await reader.read()
      if (next.done || signal.aborted) return
      yield next.value
    }
  } finally {
    signal.removeEventListener('abort', cancel)
    reader.releaseLock()
  }
}
