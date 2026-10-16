/** One immutable operator owns a deployment's task data across browser sessions. */
import { constants } from 'node:fs'
import { link, mkdir, open, unlink, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { dirname, isAbsolute } from 'node:path'

/** Pin the configured issuer/subject before admitting any owner transport.
 * @param path - Absolute private metadata path retained with the task data.
 * @param issuer - Exact verified deployment issuer.
 * @param subject - Only authorized immutable subject.
 * @returns after the existing or newly published record matches the operator.
 */
export async function bindOwner(path: string, issuer: string, subject: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error('OIDC owner record path must be absolute')
  const expected = JSON.stringify({ version: 1, issuer, subject }) + '\n'
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const temporary = path + '.' + randomUUID() + '.tmp'
  await writeFile(temporary, expected, { flag: 'wx', mode: 0o600, flush: true })
  try {
    try { await link(temporary, path) } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    }
  } finally { await unlink(temporary) }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const stat = await file.stat()
    if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077) !== 0
      || (process.getuid !== undefined && stat.uid !== process.getuid())) throw new Error('Unsafe OIDC owner record')
    const actual = JSON.parse(await file.readFile('utf8')) as Record<string, unknown>
    if (actual.version !== 1 || actual.issuer !== issuer || actual.subject !== subject
      || Object.keys(actual).length !== 3) throw new Error('OIDC task data belongs to another identity')
  } finally { await file.close() }
}
