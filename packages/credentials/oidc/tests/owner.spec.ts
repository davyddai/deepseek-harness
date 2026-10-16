/** Durable operator ownership without credentials or model calls. */
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it } from 'vitest'
import { bindOwner } from '../src/owner.ts'
const directories: string[] = []
afterEach(async () => { await Promise.all(directories.splice(0).map(path => rm(path, { recursive: true, force: true }))) })
async function fixture() { const directory = await mkdtemp(join(tmpdir(), 'dsh-oidc-owner-')); directories.push(directory); return join(directory, 'owner.json') }
it('restores the same issuer and subject and never overwrites a foreign identity', async () => {
  const path = await fixture()
  await Promise.all([bindOwner(path, 'https://issuer.test/realm', 'owner'), bindOwner(path, 'https://issuer.test/realm', 'owner')])
  const original = await readFile(path, 'utf8')
  expect((await stat(path)).mode & 0o777).toBe(0o600)
  await expect(bindOwner(path, 'https://issuer.test/realm', 'other')).rejects.toThrow('another identity')
  await expect(bindOwner(path, 'https://other.test/realm', 'owner')).rejects.toThrow('another identity')
  expect(await readFile(path, 'utf8')).toBe(original)
})
it('rejects malformed records, symlinks and relative deployment paths', async () => {
  const path = await fixture()
  await writeFile(path, '{}', { mode: 0o600 })
  await expect(bindOwner(path, 'https://issuer.test', 'owner')).rejects.toThrow('another identity')
  await symlink(path, path + '-link')
  await expect(bindOwner(path + '-link', 'https://issuer.test', 'owner')).rejects.toThrow()
  await expect(bindOwner('relative.json', 'https://issuer.test', 'owner')).rejects.toThrow('absolute')
})
