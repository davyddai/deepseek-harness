import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it, vi } from 'vitest'
import { bridge } from '../src/http-bridge.ts'
import { Peer } from '../src/peer.ts'

const PEER = new Peer(new Context(), { principal: { kind: 'owner' } })

describe('HTTP bridge abort', () => {
  it('destroys a declared-oversize request instead of draining it', async () => {
    const destroyed: true[] = []
    const request = Readable.from([]) as IncomingMessage
    Object.assign(request, {
      url: '/api/session.prompt',
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': '999999' },
      destroy: () => { destroyed.push(true) },
    })
    let status: number | undefined
    let headers: unknown
    const response = Object.assign(new EventEmitter(), {
      writableEnded: false,
      writeHead(code: number, values?: unknown) { status = code; headers = values; return this },
      write() { return true },
      end(this: { writableEnded: boolean }) { this.writableEnded = true; return this },
    }) as unknown as ServerResponse

    await bridge(request, response, {
      requestBodyMode: () => 'buffered',
      fetch: () => { throw new Error('a rejected request must never reach the handler') },
    }, PEER, 1000)
    // The socket must not stay parked draining a body the client can trickle
    // at will after the rejection — same discipline as the chunked overrun.
    expect(status).toBe(413)
    expect(headers).toMatchObject({ connection: 'close' })
    expect(destroyed).toHaveLength(1)
  })

  it('aborts a pending native picker request when the browser disconnects', async () => {
    const body = JSON.stringify({
      type: 'client-request', rpcId: 'picker-1', method: 'directoryPicker/pick', payload: { args: {} },
    })
    const request = Readable.from([Buffer.from(body)]) as IncomingMessage
    Object.assign(request, {
      url: '/api/directoryPicker/pick',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
    })

    const response = Object.assign(new EventEmitter(), {
      writableEnded: false,
      writeHead() { return this },
      write() { return true },
      end() { this.writableEnded = true; return this },
    }) as unknown as ServerResponse

    let resolveStarted!: () => void
    const started = new Promise<void>((resolve) => { resolveStarted = resolve })
    let carrierSignal: AbortSignal | undefined
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered',
      fetch: async (input) => {
        const fetchRequest = input
        carrierSignal = fetchRequest.signal
        resolveStarted()
        if (!fetchRequest.signal.aborted) {
          await new Promise<void>((resolve) => {
            fetchRequest.signal.addEventListener('abort', () => { resolve() }, { once: true })
          })
        }
        return Response.json({ aborted: fetchRequest.signal.aborted })
      },
    }, PEER, Number.MAX_SAFE_INTEGER)
    await started
    response.emit('close')
    await pending
    expect(carrierSignal?.aborted).toBe(true)
  })

  it.each(['write', 'backpressure'])('finishes a multipart response without further writes when the client closes during %s', async (phase) => {
    const request = Readable.from([]) as IncomingMessage
    Object.assign(request, { url: '/api/workspaceFiles/readBytes', method: 'GET', headers: {} })
    const body = new FormData()
    body.set('metadata', '{}')
    body.set('data', new Blob([new Uint8Array(16 * 1024 * 1024)]))
    let writes = 0
    let cleaningUp = false
    const response = Object.assign(new EventEmitter(), {
      destroyed: false,
      writableEnded: false,
      writeHead() { return this },
      write() {
        writes++
        if (writes === 1) {
          const close = (): void => { response.destroyed = true; response.emit('close') }
          if (phase === 'write') close()
          else queueMicrotask(close)
        }
        return cleaningUp
      },
      end() { this.writableEnded = true; return this },
    })
    let settled = false
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered',
      fetch: async () => new Response(body),
    }, PEER).then(() => { settled = true })
    try {
      await expect.poll(() => settled).toBe(true)
      expect(writes).toBe(1)
      expect(response.listenerCount('drain')).toBe(0)
    } finally {
      // Release a regressed bridge parked after the one close event.
      cleaningUp = true
      response.emit('drain')
      await pending
    }
  })

  it('discards bytes returned after the client disconnects', async () => {
    const request = Readable.from([]) as IncomingMessage
    Object.assign(request, { url: '/api/workspaceFiles/readBytes', method: 'GET', headers: {} })
    const response = Object.assign(new EventEmitter(), {
      destroyed: false,
      writableEnded: false,
      writeHead() { return this },
      write() { throw new Error('a disconnected response must not receive bytes') },
      end() { this.writableEnded = true; return this },
    })
    const started = Promise.withResolvers<undefined>()
    let controller!: ReadableStreamDefaultController<Uint8Array>
    const body = new ReadableStream<Uint8Array>({
      start(value) { controller = value },
      pull() { started.resolve(undefined) },
    })
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered',
      fetch: async () => new Response(body),
    }, PEER)
    await started.promise
    response.emit('close')
    controller.enqueue(Uint8Array.of(1))
    controller.close()
    await pending
  })

  it('streams a declared 2.19 GiB request before the body ends and bypasses the JSON buffer cap', async () => {
    const request = new Readable({ read() {} }) as IncomingMessage
    Object.assign(request, {
      url: '/api/session/uploadFileBinary?sessionId=s1',
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'content-length': String(Math.ceil(2.19 * 1024 ** 3)),
      },
    })
    let status: number | undefined
    const responseBytes: Uint8Array[] = []
    const response = Object.assign(new EventEmitter(), {
      writableEnded: false,
      writeHead(code: number) { status = code; return this },
      write(chunk: Uint8Array) { responseBytes.push(chunk); return true },
      end(this: { writableEnded: boolean }) { this.writableEnded = true; return this },
    }) as unknown as ServerResponse

    let resolveStarted!: () => void
    const started = new Promise<void>((resolve) => { resolveStarted = resolve })
    const received: Uint8Array[] = []
    const pending = bridge(request, response, {
      requestBodyMode: () => 'streaming',
      fetch: async (input) => {
        resolveStarted()
        if (input.body === null) throw new Error('streaming request lost its body')
        for await (const chunk of input.body) received.push(chunk)
        return new Response('stored')
      },
    }, PEER, 1)

    await started
    expect(received).toEqual([])
    request.push(Buffer.from([1, 2]))
    request.push(Buffer.from([3, 4]))
    request.push(null)
    await pending
    expect(status).toBe(200)
    expect(received).toEqual([Uint8Array.of(1, 2), Uint8Array.of(3, 4)])
    expect(Buffer.concat(responseBytes).toString()).toBe('stored')
  })

  it('closes an unread streaming request after returning an early validation response', async () => {
    const destroyed: true[] = []
    const request = new Readable({ read() {} }) as IncomingMessage
    Object.assign(request, {
      url: '/api/session/uploadFileBinary',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      destroy: () => { destroyed.push(true) },
    })
    let status: number | undefined
    let headers: unknown
    const response = Object.assign(new EventEmitter(), {
      writableEnded: false,
      writeHead(code: number, values?: unknown) { status = code; headers = values; return this },
      write() { return true },
      end(this: { writableEnded: boolean }) { this.writableEnded = true; return this },
    }) as unknown as ServerResponse

    await bridge(request, response, {
      requestBodyMode: () => 'streaming',
      fetch: () => Promise.resolve(new Response(null, { status: 415 })),
    }, PEER, 1)
    expect(status).toBe(415)
    expect(headers).toMatchObject({ connection: 'close' })
    expect(destroyed).toEqual([true])
  })
})


describe('external session HTTP revocation', () => {
  function transport() {
    const request = Readable.from([]) as IncomingMessage
    Object.assign(request, { url: '/api/fixture', method: 'GET', headers: {} })
    const events = new EventEmitter()
    const response = Object.assign(events, {
      destroyed: false, writableEnded: false, headersWritten: 0, bytesWritten: 0,
      writeHead() { this.headersWritten++; return this },
      write(chunk: Uint8Array) { this.bytesWritten += chunk.byteLength; return true },
      end() { this.writableEnded = true; return this },
      destroy() { this.destroyed = true; events.emit('close'); return this },
    })
    return { request, response, peer: new Peer(new Context(), { principal: { kind: 'owner' } }) }
  }

  it('completes an ordinary external response without destroying buffered output', async () => {
    const { request, response, peer } = transport()
    await bridge(request, response, {
      requestBodyMode: () => 'buffered', fetch: async () => new Response('done'),
    }, peer, undefined, peer.signal)
    expect(response.writableEnded).toBe(true)
    expect(response.destroyed).toBe(false)
    expect(response.bytesWritten).toBe(4)
    await peer.dispose()
  })

  it('bounds teardown of a handler ignoring cancellation and discards its late response', async () => {
    vi.useFakeTimers()
    const { request, response, peer } = transport()
    const started = Promise.withResolvers<undefined>()
    const late = Promise.withResolvers<Response>()
    let signal: AbortSignal | undefined
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered',
      fetch: async (req) => { signal = req.signal; started.resolve(undefined); return late.promise },
    }, peer, undefined, peer.signal)
    try {
      await started.promise
      const disposal = peer.dispose()
      await Promise.resolve()
      expect(response.destroyed).toBe(true)
      expect(signal?.aborted).toBe(true)
      await vi.advanceTimersByTimeAsync(1000)
      await disposal
      await pending
      late.resolve(new Response('late secret response'))
      await vi.advanceTimersByTimeAsync(0)
      expect(response.headersWritten).toBe(0)
      expect(response.bytesWritten).toBe(0)
      expect(response.writableEnded).toBe(false)
    } finally { late.resolve(new Response()); vi.useRealTimers(); await peer.dispose() }
  })

  it('closes a never-ending response reader without waiting for its underlying cancel', async () => {
    const { request, response, peer } = transport()
    const reading = Promise.withResolvers<undefined>()
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
      pull() { reading.resolve(undefined) },
      cancel() { cancelled = true; return new Promise<void>(() => {}) },
    })
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered', fetch: async () => new Response(body),
    }, peer, undefined, peer.signal)
    await reading.promise
    await expect.poll(() => response.headersWritten).toBe(1)
    await peer.dispose()
    await pending
    expect(cancelled).toBe(true)
    expect(response.destroyed).toBe(true)
    expect(response.bytesWritten).toBe(0)
  })

  it('awaits cooperative handler cleanup before completing revocation', async () => {
    const { request, response, peer } = transport()
    const started = Promise.withResolvers<undefined>()
    const cleanup = Promise.withResolvers<undefined>()
    let cleaned = false
    const pending = bridge(request, response, {
      requestBodyMode: () => 'buffered', fetch: async (req) => {
        started.resolve(undefined)
        await new Promise<void>(resolve => req.signal.addEventListener('abort', () => resolve(), { once: true }))
        await cleanup.promise
        cleaned = true
        return new Response('done')
      },
    }, peer, undefined, peer.signal)
    await started.promise
    let disposed = false
    const disposal = peer.dispose().then(() => { disposed = true })
    await Promise.resolve()
    expect(disposed).toBe(false)
    expect(response.destroyed).toBe(true)
    cleanup.resolve(undefined)
    await disposal
    await pending
    expect(cleaned).toBe(true)
    expect(response.headersWritten).toBe(0)
  })
})
