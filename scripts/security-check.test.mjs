/**
 * SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial
 * Project lextelligent
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { scanText } from './security-check.mjs'

test('catches private keys, tokens and credentials', () => {
  const hits = scanText([
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'password: "hunter2secret"',
  ].join('\n'))
  const labels = hits.map((h) => h.label)
  assert.ok(labels.includes('Private key block'))
  assert.ok(labels.includes('GitHub token'))
  assert.ok(labels.includes('Hardcoded password'))
})

test('catches internal IPs, host paths and SSNs', () => {
  const hits = scanText([
    'connect to 192.168.4.22 now',
    'run from /home/someone/project',
    'ssn 123-45-6789',
  ].join('\n'))
  const labels = hits.map((h) => h.label)
  assert.ok(labels.includes('IP address'))
  assert.ok(labels.includes('Internal filesystem path'))
  assert.ok(labels.includes('SSN'))
})

test('allows synthetic addresses and documentation IPs', () => {
  const hits = scanText([
    'From: a@example.com',
    'user@[192.0.2.1]',
    'bind to 0.0.0.0',
  ].join('\n'))
  assert.deepEqual(hits, [])
})
