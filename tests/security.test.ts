import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  SECURITY_HEADERS,
  buildHtmlCsp,
  ALLOWED_RPC_METHODS,
  isAllowedRpcMethod,
  isAllowedFetchSite,
  validateFetchMetadata,
  normalizeIp,
  isTrustedProxyAddress,
  resolveClientIp,
  checkApiRateLimit,
  clearRateLimitsForTests,
  acquireProposalLock,
  sanitizeRpcErrorMessage,
  resolveKristaRpcConfig,
  configureProposalsFileForTests,
  readProposalsAtomically,
  writeProposalsAtomically
} from '../server/utils/security.ts'

describe('server/utils/security — HTTP Security Headers & Fetch Metadata Isolation', () => {
  it('defines immutable institutional HTTP security headers', () => {
    assert.equal(Object.isFrozen(SECURITY_HEADERS), true)
    assert.ok(SECURITY_HEADERS['Content-Security-Policy']?.includes("default-src 'self'"))
    assert.ok(SECURITY_HEADERS['Content-Security-Policy']?.includes("script-src 'self'"))
    assert.ok(SECURITY_HEADERS['Content-Security-Policy']?.includes("connect-src 'self'"))
    assert.ok(SECURITY_HEADERS['Content-Security-Policy']?.includes("frame-ancestors 'self'"))
    assert.ok(SECURITY_HEADERS['Content-Security-Policy']?.includes("object-src 'none'"))
    assert.equal(SECURITY_HEADERS['X-Frame-Options'], 'SAMEORIGIN')
    assert.equal(SECURITY_HEADERS['X-Content-Type-Options'], 'nosniff')
    assert.equal(SECURITY_HEADERS['Cross-Origin-Opener-Policy'], 'same-origin-allow-popups')
    assert.equal(SECURITY_HEADERS['Cross-Origin-Resource-Policy'], 'same-origin')

    const prodCsp = buildHtmlCsp('testNonce123==', false)
    assert.ok(prodCsp.includes("script-src 'self' 'nonce-testNonce123=='"))
    assert.equal(prodCsp.includes('ws://127.0.0.1:*'), false)
    const devCsp = buildHtmlCsp('testNonce123==', true)
    assert.ok(devCsp.includes('ws://127.0.0.1:*'))
  })

  it('enforces Sec-Fetch-Site resource isolation against cross-site and mutating same-site requests', () => {
    assert.equal(isAllowedFetchSite(undefined), true)
    assert.equal(isAllowedFetchSite('same-origin', 'POST'), true)
    assert.equal(isAllowedFetchSite('same-site', 'GET'), true)
    assert.equal(isAllowedFetchSite('same-site', 'POST'), false)
    assert.equal(isAllowedFetchSite('none', 'POST'), true)
    assert.equal(isAllowedFetchSite('cross-site', 'POST'), false)

    assert.equal(validateFetchMetadata({ 'sec-fetch-site': 'same-origin' }, 'POST').allowed, true)
    const rejectedSameSitePost = validateFetchMetadata({ 'sec-fetch-site': 'same-site' }, 'POST')
    assert.equal(rejectedSameSitePost.allowed, false)
    const rejected = validateFetchMetadata({ 'sec-fetch-site': 'cross-site' }, 'POST')
    assert.equal(rejected.allowed, false)
    assert.ok(rejected.reason?.includes('Cross-site request blocked'))
  })
})

describe('server/utils/security — Anti-Spoofing IP Resolution, Rate Limiting & Mutex Lock', () => {
  afterEach(() => {
    clearRateLimitsForTests()
    configureProposalsFileForTests(undefined)
  })

  it('prevents X-Forwarded-For spoofing from untrusted peers while honoring trusted loopback proxies', () => {
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1')
    assert.equal(isTrustedProxyAddress('127.0.0.1'), true)
    assert.equal(isTrustedProxyAddress('::1'), true)
    assert.equal(isTrustedProxyAddress('198.51.100.42'), false)

    const fakeEventUntrusted = {
      node: {
        req: {
          socket: { remoteAddress: '198.51.100.42' },
          headers: { 'x-forwarded-for': '203.0.113.99' }
        }
      }
    } as any
    // Untrusted peer attempting to spoof X-Forwarded-For -> ignored!
    assert.equal(resolveClientIp(fakeEventUntrusted, true), '198.51.100.42')

    const fakeEventTrusted = {
      node: {
        req: {
          socket: { remoteAddress: '127.0.0.1' },
          headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.99, 127.0.0.1' }
        }
      }
    } as any
    // Trusted local reverse proxy forwarding real client IP -> ignores spoofed leftmost XFF!
    assert.equal(resolveClientIp(fakeEventTrusted, true), '203.0.113.99')
  })

  it('enforces sliding-window API rate limits per client and bounds bucket map size', () => {
    assert.equal(checkApiRateLimit('proposals-post', '203.0.113.5', 3, 60_000).allowed, true)
    assert.equal(checkApiRateLimit('proposals-post', '203.0.113.5', 3, 60_000).allowed, true)
    assert.equal(checkApiRateLimit('proposals-post', '203.0.113.5', 3, 60_000).allowed, true)

    const fourth = checkApiRateLimit('proposals-post', '203.0.113.5', 3, 60_000)
    assert.equal(fourth.allowed, false)
    assert.equal(fourth.remaining, 0)
    assert.ok(fourth.retryAfterSec > 0)

    // Flood > 10,000 unique client buckets and verify eviction bounds memory without error
    for (let i = 0; i < 10_050; i++) {
      const octet3 = (i >> 8) & 0xff
      const octet4 = i & 0xff
      checkApiRateLimit('flood-test', `198.51.${octet3}.${octet4}`, 5, 60_000)
    }
    assert.equal(checkApiRateLimit('flood-test', '198.51.99.99', 5, 60_000).allowed, true)
  })

  it('prevents concurrent proposal mutations via acquireProposalLock (prevents TOCTOU race conditions)', () => {
    const releaseFirst = acquireProposalLock('global-proposals')
    assert.equal(typeof releaseFirst, 'function')

    // Second concurrent lock attempt while first is held -> returns null
    const secondAttempt = acquireProposalLock('global-proposals')
    assert.equal(secondAttempt, null)

    // After releasing first lock -> subsequent lock succeeds
    releaseFirst!()
    const thirdAttempt = acquireProposalLock('global-proposals')
    assert.equal(typeof thirdAttempt, 'function')
    thirdAttempt!()
  })

  it('redacts credentials, URLs, and server paths in sanitizeRpcErrorMessage', () => {
    const rawErr = new Error(
      'Failed to connect to http://admin:supersecret@127.0.0.1:19998/wallet at /home/server/secret/node.dat and 127.0.0.1:27998 /var/lib/krista/wallet.dat /etc/kristatech/conf'
    )
    const sanitized = sanitizeRpcErrorMessage(rawErr)
    assert.equal(sanitized.includes('supersecret'), false)
    assert.equal(sanitized.includes('127.0.0.1:19998'), false)
    assert.equal(sanitized.includes('127.0.0.1:27998'), false)
    assert.equal(sanitized.includes('/home/server/secret'), false)
    assert.equal(sanitized.includes('/var/lib/krista'), false)
    assert.equal(sanitized.includes('/etc/kristatech'), false)
  })

  it('rejects non-loopback plaintext HTTP RPC endpoints unless explicitly allowed', () => {
    const prevUser = process.env.NUXT_RPC_USER
    const prevPass = process.env.NUXT_RPC_PASSWORD
    const prevUrl = process.env.NUXT_RPC_URL
    const prevAllow = process.env.NUXT_ALLOW_INSECURE_REMOTE_RPC
    try {
      process.env.NUXT_RPC_USER = 'rpcu'
      process.env.NUXT_RPC_PASSWORD = 'rpcp'
      process.env.NUXT_RPC_URL = 'http://203.0.113.10:27998'
      delete process.env.NUXT_ALLOW_INSECURE_REMOTE_RPC
      assert.throws(() => resolveKristaRpcConfig(), /non-loopback/i)
    } finally {
      if (prevUser === undefined) delete process.env.NUXT_RPC_USER
      else process.env.NUXT_RPC_USER = prevUser
      if (prevPass === undefined) delete process.env.NUXT_RPC_PASSWORD
      else process.env.NUXT_RPC_PASSWORD = prevPass
      if (prevUrl === undefined) delete process.env.NUXT_RPC_URL
      else process.env.NUXT_RPC_URL = prevUrl
      if (prevAllow === undefined) delete process.env.NUXT_ALLOW_INSECURE_REMOTE_RPC
      else process.env.NUXT_ALLOW_INSECURE_REMOTE_RPC = prevAllow
    }
  })

  it('writes and reads proposals atomically with 0o600 file permissions', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'krista-treasury-test-'))
    const testFile = path.join(tmpDir, 'proposals.json')
    configureProposalsFileForTests(testFile)

    const initial = readProposalsAtomically()
    assert.deepEqual(initial, [])

    const sampleProposals = [
      {
        id: 'prop-1',
        txHash: 'a'.repeat(64),
        rawTxHex: '02000000',
        targetAddress: 'KTeRC2Kj8hXcuzRohxPp2LtYFRJm2BceRoP',
        amount: 250,
        signatures: [],
        status: 'pending' as const,
        createdAt: 1700000000000
      }
    ]
    writeProposalsAtomically(sampleProposals)

    const loaded = readProposalsAtomically()
    assert.equal(loaded.length, 1)
    assert.equal(loaded[0]!.id, 'prop-1')

    const stat = await fs.stat(testFile)
    assert.equal(stat.mode & 0o777, 0o600)

    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it('enforces a strict KristaTech RPC method allowlist and blocks wallet-draining RPC methods', () => {
    assert.equal(ALLOWED_RPC_METHODS.has('getactivequorum'), true)
    assert.equal(isAllowedRpcMethod('getblockchaininfo'), true)
    assert.equal(isAllowedRpcMethod('getactivequorum'), true)
    assert.equal(isAllowedRpcMethod('sendrawtransaction'), true)

    // Disallowed sensitive wallet/admin RPCs must be rejected
    assert.equal(isAllowedRpcMethod('dumpprivkey'), false)
    assert.equal(isAllowedRpcMethod('sendtoaddress'), false)
    assert.equal(isAllowedRpcMethod('stop'), false)
    assert.equal(isAllowedRpcMethod(''), false)
  })
})
