import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import type { H3Event } from 'h3'
import { getRequestHeader } from 'h3'

/**
 * Immutable defense-in-depth HTTP security headers (modern-web-guidance: security §1.4, §3.4, §3.5, §3.7).
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy':
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy':
    "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'"
})

/**
 * Normalizes IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
 */
export function normalizeIp(rawIp: unknown): string {
  const cleaned = String(rawIp || '').trim()
  if (!cleaned) return '127.0.0.1'
  if (cleaned.startsWith('::ffff:')) {
    return cleaned.slice(7)
  }
  if (cleaned === '::1') {
    return '127.0.0.1'
  }
  return cleaned
}

export function isTrustedProxyAddress(ip: string): boolean {
  const norm = normalizeIp(ip)
  if (norm === '127.0.0.1' || norm === '::1') return true
  if (norm.startsWith('10.') || norm.startsWith('192.168.')) return true
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(norm)) return true
  return false
}

/**
 * Resolves the client IP safely without allowing arbitrary X-Forwarded-For spoofing.
 * Forwarded headers are only trusted when NUXT_TRUST_PROXY=true AND the direct socket IP is a local/private proxy.
 */
export function resolveClientIp(event: H3Event, trustProxyOverride?: boolean): string {
  const socketIp = normalizeIp(event?.node?.req?.socket?.remoteAddress || '127.0.0.1')
  const trustProxy =
    trustProxyOverride !== undefined
      ? trustProxyOverride
      : process.env.NUXT_TRUST_PROXY === 'true'

  if (trustProxy && isTrustedProxyAddress(socketIp)) {
    const xff = getRequestHeader(event, 'x-forwarded-for')
    if (xff) {
      const firstHop = xff.split(',')[0]?.trim()
      if (firstHop && /^[0-9a-fA-F:.]{3,45}$/.test(firstHop)) {
        return normalizeIp(firstHop)
      }
    }
    const realIp = getRequestHeader(event, 'x-real-ip')?.trim()
    if (realIp && /^[0-9a-fA-F:.]{3,45}$/.test(realIp)) {
      return normalizeIp(realIp)
    }
  }

  return socketIp
}

/**
 * Enforces Fetch Metadata resource isolation (Sec-Fetch-Site) per modern-web-guidance: security §3.7.
 * Rejects cross-site requests to non-navigational API endpoints while permitting same-origin,
 * same-site, direct user navigation, and legacy user agents that omit Sec-Fetch-Site.
 */
export function isAllowedFetchSite(
  secFetchSite: unknown,
  method = 'GET',
  secFetchMode?: unknown,
  secFetchDest?: unknown
): boolean {
  if (typeof secFetchSite !== 'string' || secFetchSite.trim() === '') {
    return true
  }

  const site = secFetchSite.trim().toLowerCase()
  if (site === 'same-origin' || site === 'same-site' || site === 'none') {
    return true
  }

  const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : 'GET'
  const mode = typeof secFetchMode === 'string' ? secFetchMode.trim().toLowerCase() : ''
  const dest = typeof secFetchDest === 'string' ? secFetchDest.trim().toLowerCase() : ''

  if (
    site === 'cross-site' &&
    mode === 'navigate' &&
    normalizedMethod === 'GET' &&
    dest !== 'object' &&
    dest !== 'embed' &&
    dest !== 'iframe'
  ) {
    return true
  }

  return false
}

export function validateFetchMetadata(
  headers: Record<string, string | undefined>,
  method: string
): { allowed: boolean; reason?: string } {
  const site = headers['sec-fetch-site']
  const mode = headers['sec-fetch-mode']
  const dest = headers['sec-fetch-dest']
  if (isAllowedFetchSite(site, method, mode, dest)) {
    return { allowed: true }
  }
  return {
    allowed: false,
    reason: `Cross-site request blocked by Fetch Metadata policy (Sec-Fetch-Site: ${String(site).trim()})`
  }
}

/**
 * Per-IP in-memory rate limiter for API endpoints to prevent DoS & RPC flooding.
 */
interface RateWindow {
  count: number
  resetAt: number
}

const rateLimitBuckets = new Map<string, RateWindow>()
const MAX_RATE_BUCKETS = 10_000

export function checkApiRateLimit(
  bucket: string,
  clientIp: string,
  maxRequests: number,
  windowMs: number
): { allowed: boolean; remaining: number; retryAfterSec: number } {
  const now = Date.now()

  if (rateLimitBuckets.size > MAX_RATE_BUCKETS) {
    for (const [k, v] of rateLimitBuckets.entries()) {
      if (v.resetAt <= now) {
        rateLimitBuckets.delete(k)
      }
    }
  }

  const key = `${bucket}:${normalizeIp(clientIp)}`
  const existing = rateLimitBuckets.get(key)

  if (!existing || existing.resetAt <= now) {
    rateLimitBuckets.set(key, {
      count: 1,
      resetAt: now + windowMs
    })
    return {
      allowed: true,
      remaining: Math.max(0, maxRequests - 1),
      retryAfterSec: 0
    }
  }

  existing.count += 1
  if (existing.count > maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000))
    }
  }

  return {
    allowed: true,
    remaining: Math.max(0, maxRequests - existing.count),
    retryAfterSec: 0
  }
}

/**
 * In-flight concurrency lock to prevent TOCTOU race conditions during proposal creation and signing.
 */
const activeProposalLocks = new Map<string, number>()
const PROPOSAL_LOCK_TTL_MS = 20_000

export function acquireProposalLock(lockKey = 'global-proposals'): (() => void) | null {
  const now = Date.now()
  for (const [k, expires] of activeProposalLocks.entries()) {
    if (expires <= now) {
      activeProposalLocks.delete(k)
    }
  }

  const key = `proposal-lock:${lockKey}`
  if (activeProposalLocks.has(key)) {
    return null
  }

  activeProposalLocks.set(key, now + PROPOSAL_LOCK_TTL_MS)
  let released = false
  return () => {
    if (released) return
    released = true
    activeProposalLocks.delete(key)
  }
}

export function clearRateLimitsForTests(): void {
  rateLimitBuckets.clear()
  activeProposalLocks.clear()
}

/**
 * Sanitizes RPC or internal errors so credentials, local file paths, or internal ports are not leaked.
 */
export function sanitizeRpcErrorMessage(
  err: unknown,
  fallback = 'RPC operation failed'
): string {
  const raw = err instanceof Error ? err.message : String(err || '')
  if (!raw) return fallback

  const cleaned = raw
    .replace(/https?:\/\/[^\s]+/gi, '[redacted-url]')
    .replace(/Basic\s+[A-Za-z0-9+/=]+/gi, 'Basic [redacted]')
    .replace(/\/home\/[^\s:]+/gi, '[redacted-path]')
    .slice(0, 240)
    .trim()

  return cleaned || fallback
}

/**
 * Atomic JSON store for Treasury proposals with restrictive file permissions (0o600).
 */
let customProposalsFilePath: string | null = null

export function configureProposalsFileForTests(filePath?: string): void {
  customProposalsFilePath = filePath || null
}

export function getProposalsFilePath(): string {
  if (customProposalsFilePath) {
    return customProposalsFilePath
  }
  if (process.env.NUXT_PROPOSALS_FILE) {
    return path.resolve(process.env.NUXT_PROPOSALS_FILE)
  }
  return path.resolve(process.cwd(), 'proposals.json')
}

export function readProposalsAtomically(): any[] {
  const filePath = getProposalsFilePath()
  if (!fs.existsSync(filePath)) {
    return []
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf-8')
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function writeProposalsAtomically(proposals: any[]): void {
  const filePath = getProposalsFilePath()
  const dir = path.dirname(filePath)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  }
  const tmpFile = `${filePath}.tmp.${crypto.randomUUID()}`
  const payload = JSON.stringify(Array.isArray(proposals) ? proposals : [], null, 2)
  fs.writeFileSync(tmpFile, payload, { encoding: 'utf-8', mode: 0o600 })
  fs.renameSync(tmpFile, filePath)
}

/**
 * Strict allowlist of KristaTech JSON-RPC methods used by the Treasury Portal.
 */
export const ALLOWED_RPC_METHODS: ReadonlySet<string> = new Set([
  'getblockchaininfo',
  'getactivequorum',
  'getblockhash',
  'getblock',
  'listmasternodes',
  'getadamminers',
  'decoderawtransaction',
  'gettxout',
  'sendrawtransaction'
])

export function isAllowedRpcMethod(method: unknown): method is string {
  return typeof method === 'string' && ALLOWED_RPC_METHODS.has(method.trim())
}

/**
 * Resolves KristaTech RPC URL and Basic Auth credentials from environment variables or
 * local ~/.kristatech/kristatech.conf and ~/.kristatech/.cookie (matching Explorer RPC discovery).
 */
export function resolveKristaRpcConfig(): { url: string; authBase64: string } {
  let host = '127.0.0.1'
  let port = '27998'
  let user = process.env.NUXT_RPC_USER || ''
  let pass = process.env.NUXT_RPC_PASSWORD || ''

  if (!user || !pass) {
    try {
      const dataDir = path.join(os.homedir(), '.kristatech')
      const confPath = path.join(dataDir, 'kristatech.conf')
      if (fs.existsSync(confPath)) {
        const lines = fs.readFileSync(confPath, 'utf-8').split(/\r?\n/)
        for (const rawLine of lines) {
          const line = rawLine.trim()
          if (!line || line.startsWith('#')) continue
          const eqIdx = line.indexOf('=')
          if (eqIdx === -1) continue
          const key = line.slice(0, eqIdx).trim().toLowerCase()
          const val = line.slice(eqIdx + 1).trim()
          if (!val) continue
          if (key === 'rpcuser' && !user) user = val
          else if (key === 'rpcpassword' && !pass) pass = val
          else if (key === 'rpcport') port = val
          else if (key === 'rpcconnect') host = val
        }
      }
      if (!user || !pass) {
        const cookiePath = path.join(dataDir, '.cookie')
        if (fs.existsSync(cookiePath)) {
          const cookie = fs.readFileSync(cookiePath, 'utf-8').trim()
          const sep = cookie.indexOf(':')
          if (sep > 0) {
            user = cookie.slice(0, sep)
            pass = cookie.slice(sep + 1)
          }
        }
      }
    } catch {
      // Ignore local config read errors and use fallback defaults
    }
  }

  const finalUser = user || 'kristarpc'
  const finalPass = pass || 'kristapassword'
  const url = process.env.NUXT_RPC_URL || `http://${host}:${port}`
  const authBase64 = Buffer.from(`${finalUser}:${finalPass}`).toString('base64')
  return { url, authBase64 }
}

export async function callKristaRpc(method: string, params: any[] = []): Promise<any> {
  if (!isAllowedRpcMethod(method)) {
    throw new Error(`Disallowed RPC method: ${String(method)}`)
  }
  const { url, authBase64 } = resolveKristaRpcConfig()
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${authBase64}`
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'nuxt-api',
      method,
      params
    }),
    signal: AbortSignal.timeout(8000)
  })
  if (!response.ok) {
    throw new Error(`RPC call ${method} failed: ${response.statusText}`)
  }
  const json: any = await response.json()
  if (json?.error) {
    throw new Error(json.error.message || `RPC error on ${method}`)
  }
  return json.result
}
