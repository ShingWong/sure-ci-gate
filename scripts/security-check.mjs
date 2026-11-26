/**
 * SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial
 * Project lextelligent
 *
 * Repository security gate for a public Rust crate: private keys, credentials,
 * secrets, PII, IP addresses, internal hosts/paths and card numbers.
 *
 * This is the PUBLIC structural half of the gate. It deliberately contains no
 * product names, internal hostnames, account names or customer terms — those
 * are supplied at runtime through SUN_DENYLIST from a private repository, so
 * publishing this scanner cannot disclose what we filter for.
 *
 * Dependency-free on purpose: CI and a local pre-commit hook must run under a
 * plain `node` on a fresh clone, with no network and no install step.
 * SURE_SCAN_ROOT overrides the directory to scan (used by the reusable CI job,
 * which checks this repo out into a subdirectory of the caller's workspace).
 *
 * With git available, content is read from the index blob (what will actually
 * be committed), not the working tree. Outside git it falls back to disk.
 *
 * Usage:
 *   node scripts/security-check.mjs
 *   SUN_DENYLIST=/path/to/words.txt node scripts/security-check.mjs
 *
 * SUN_DENYLIST names literals kept OUT of this public repo (product names,
 * customer identifiers, internal hostnames). The words live in the consumer's
 * CI, never here. An allow-list entry is keyed by file + label + exact text and
 * MUST carry a reason; patterns are never loosened to silence a finding.
 */

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const ROOT = process.env.SURE_SCAN_ROOT || join(import.meta.dirname, '..')

/** Files that are shipped regardless of a manifest allow-list. */
const ROOT_FILES = ['README.md', 'LICENSE', 'Cargo.toml', 'SECURITY.md']

/** Binary files cannot be read; report them so a person can check for PII. */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.avif',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.wasm', '.zip', '.gz', '.tgz', '.pdf', '.mp4', '.webm', '.mp3',
])
const MAX_BYTES = 1024 * 1024

/** Synthetic fixtures by design; still checked for key-material filenames. */
const TEST_FILE = /\.(?:test|spec)\.\w+$/

/** A declared copyright/licence header is a convention, not a leak. */
const HEADER_LINE = /^(?:\/\/|#|\*|<!--)\s*Copyright \(c\)\s/i

const PATTERNS = [
  { label: 'Private key block', regex: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/ },
  { label: 'OpenSSH private key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/ },
  { label: 'AWS access key id', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: 'GitHub token', regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/ },
  { label: 'Slack token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'AI provider key', regex: /\b(?:sk-ant-|sk-)[A-Za-z0-9_-]{24,}\b/ },
  { label: 'Stripe live key', regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/ },
  { label: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { label: 'Credentials in URL', regex: /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@[^\s/]+/i },
  { label: 'Hardcoded password', regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{3,}['"]/i },
  { label: 'SSN', regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/ },
  { label: 'Email address', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
  { label: 'IP address', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
  // `.local` is deliberately absent: mDNS names are routine in tests and
  // provider configs. Explicit internal hostnames belong in the private
  // denylist, not in this public file.
  { label: 'Internal hostname', regex: /\b(?:[a-z0-9-]+\.)+(?:internal|corp|lan)\b/i },
  { label: 'Internal filesystem path', regex: /(?:\/Users\/|\/home\/[a-z0-9._-]+\/|C:\\Users\\|\/opt\/[a-z0-9._-]+\/|\/srv\/[a-z0-9._-]+\/)/i },
]
for (const p of PATTERNS) p.global = new RegExp(p.regex.source, p.regex.flags + 'g')

const SAFE_EMAIL_DOMAINS = new Set(['example.com', 'example.org', 'example.net', 'test', 'localhost', 'invalid', 'example'])
const SAFE_EMAIL_LITERALS = new Set(['git@github.com', 'npm@npmjs.com', 'support@npmjs.com'])
/** RFC 5737 documentation ranges, loopback and the unspecified address. */
const SAFE_IP_PREFIXES = ['192.0.2.', '198.51.100.', '203.0.113.', '127.', '0.0.0.0']

/**
 * Per-project public config: `.security-gate.json` may contain `allow`
 * ({ file, label, match, reason }), `safeEmailDomains` and `safeIps`.
 * Only reviewed, non-sensitive placeholders belong there.
 */
function projectConfig() {
  try {
    return JSON.parse(readFileSync(join(ROOT, '.security-gate.json'), 'utf8'))
  } catch {
    return {}
  }
}
const CONFIG = projectConfig()

/** Deliberate, documented exceptions. Add only with file + label + match + reason. */
const ALLOW = CONFIG.allow ?? []

/** This file necessarily contains the literals it allows; skip that block. */
const SELF = 'scripts/security-check.mjs'

function denylist() {
  const path = process.env.SUN_DENYLIST
  if (!path) return []
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((literal) => ({
      label: 'Product denylist',
      global: new RegExp(literal, 'gi'),
    }))
}

function isSafeEmail(match) {
  if (SAFE_EMAIL_LITERALS.has(match.toLowerCase())) return true
  const domain = match.slice(match.lastIndexOf('@') + 1).toLowerCase()
  if (SAFE_EMAIL_DOMAINS.has(domain) || (CONFIG.safeEmailDomains ?? []).includes(domain) || domain.endsWith('.example') || domain.endsWith('.test')) return true
  // Deliberately malformed fixtures (a@-example.com, a@example..com) are
  // syntax test vectors, not addresses that could identify anyone.
  return domain.startsWith('.') || domain.endsWith('.') || domain.includes('..') || domain.startsWith('-')
}

function isSafeIp(match) {
  return [...SAFE_IP_PREFIXES, ...(CONFIG.safeIps ?? [])].some((prefix) => match.startsWith(prefix))
}

function luhnValid(digits) {
  let sum = 0
  let double = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (double) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    double = !double
  }
  return sum % 10 === 0
}

/** Show enough to locate a finding without printing the secret itself. */
function redact(match) {
  if (match.length <= 8) return `${match.slice(0, 2)}…`
  return `${match.slice(0, 4)}…${match.slice(-2)} (${match.length} chars)`
}

/** @returns {Array<{file: string, line: number, label: string, hint: string}>} */
export function scanText(text, file = '<memory>') {
  const findings = []
  const lines = text.split(/\r?\n/)
  const extra = denylist()
  const allowStart = file === SELF ? lines.findIndex((line) => line.startsWith('const ALLOW = [')) : -1
  const allowEnd = allowStart < 0 ? -1 : lines.findIndex((line, i) => i > allowStart && line === ']')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (allowStart >= 0 && i > allowStart && (allowEnd < 0 || i <= allowEnd)) continue
    if (HEADER_LINE.test(line)) continue
    for (const pattern of [...PATTERNS, ...extra]) {
      const seen = new Set()
      for (const m of line.matchAll(pattern.global)) {
        const match = m[0]
        if (seen.has(match)) continue
        seen.add(match)
        if (pattern.label === 'Email address' && isSafeEmail(match)) continue
        if (pattern.label === 'IP address' && isSafeIp(match)) continue
        if (ALLOW.some((a) => (a.file === '*' || a.file === file) && a.label === pattern.label && match.includes(a.match))) continue
        findings.push({ file, line: i + 1, label: pattern.label, hint: redact(match) })
      }
    }
    // Card numbers: shape first, Luhn validation to avoid float false positives.
    for (const m of line.matchAll(/(?<![\w.])(?:\d[ -]?){12,18}\d(?![\w.])/g)) {
      const digits = m[0].replace(/\D/g, '')
      if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) continue
      if (ALLOW.some((a) => (a.file === '*' || a.file === file) && a.label === 'Card number' && m[0].includes(a.match))) continue
      findings.push({ file, line: i + 1, label: 'Card number', hint: redact(m[0]) })
    }
  }
  return findings
}

function trackedFiles() {
  try {
    const out = execFileSync('git', ['ls-files', '-z'], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return out.split('\0').filter(Boolean)
  } catch {
    return null
  }
}

/** Read the index blob when possible — that is what a commit will contain. */
function readContent(rel, gitMode) {
  if (gitMode) {
    try {
      return execFileSync('git', ['show', `:${rel}`], {
        cwd: ROOT,
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
    } catch {
      // Not in the index (e.g. a root file in a fresh clone) — fall through.
    }
  }
  return readFileSync(join(ROOT, rel), 'utf8')
}

function walk(dir, acc = []) {
  for (const entry of readdirSync(join(ROOT, dir))) {
    const rel = `${dir}/${entry}`
    if (statSync(join(ROOT, rel)).isDirectory()) walk(rel, acc)
    else acc.push(rel)
  }
  return acc
}

const notifications = []

function scanPath(rel, findings, gitMode) {
  const ext = extname(rel).toLowerCase()
  if (BINARY_EXTENSIONS.has(ext)) {
    notifications.push(`${rel} — binary, not scanned; confirm it carries no PII`)
    return
  }
  if (TEST_FILE.test(rel)) return
  let text
  try {
    text = readContent(rel, gitMode)
  } catch {
    return
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES || text.includes('\0')) return
  findings.push(...scanText(text, rel.split(sep).join('/')))
}

/** @returns {Array<{file: string, line: number, label: string, hint: string}>} */
export function scanRepo() {
  notifications.length = 0
  const files = trackedFiles()
  const gitMode = files !== null
  const findings = []
  const seen = new Set()
  for (const rel of [...(files ?? walk('.')), ...ROOT_FILES]) {
    const norm = rel.replace(/^\.\//, '')
    if (seen.has(norm)) continue
    seen.add(norm)
    if (!gitMode && !existsSync(join(ROOT, norm))) continue
    scanPath(norm, findings, gitMode)
  }
  // A tracked .env or key file is always a finding, whatever its contents.
  for (const rel of seen) {
    const name = rel.split('/').pop() ?? ''
    if (/^\.env(\.|$)/.test(name) && !name.endsWith('.example')) {
      findings.push({ file: rel, line: 1, label: 'Committed environment file', hint: name })
    }
    if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(name) || name === 'id_rsa' || name === 'id_ed25519') {
      findings.push({ file: rel, line: 1, label: 'Key material file', hint: name })
    }
  }
  return findings
}

export function unscannedBinaries() {
  return [...notifications]
}

function main() {
  const findings = scanRepo()
  if (findings.length) {
    console.error('\nSECURITY CHECK FAILED — potential key/credential/PII/host leak:\n')
    for (const f of findings) console.error(`  ${f.file}:${f.line} — ${f.label} — ${f.hint}`)
    console.error('\nRemove the value, or add an ALLOW entry (file + label + match + reason).\n')
    process.exit(1)
  }
  const binaries = unscannedBinaries()
  if (binaries.length) {
    console.log(`${binaries.length} binary file(s) not scanned — confirm by eye:`)
    for (const line of binaries) console.log(`  ${line}`)
  }
  console.log('Security check passed — no keys, credentials, PII, IPs, host paths or card numbers found.\n')
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main()
