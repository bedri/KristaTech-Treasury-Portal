import { defineEventHandler, getRequestHeader, setHeader, createError } from 'h3'
import { SECURITY_HEADERS, validateFetchMetadata } from '../utils/security'

const MAX_API_BODY_BYTES = 262_144 // 256 KB
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export default defineEventHandler((event) => {
  // Apply defense-in-depth HTTP security headers (modern-web-guidance: security §1.4, §3.4, §3.5, §3.7)
  for (const [headerName, headerValue] of Object.entries(SECURITY_HEADERS)) {
    setHeader(event, headerName, headerValue)
  }

  const rawPath = (event.path || '').split('?')[0] || ''
  let normalizedPath = rawPath
  try {
    normalizedPath = decodeURIComponent(rawPath)
  } catch {
    throw createError({
      statusCode: 400,
      statusMessage: 'Bad Request: Malformed URL path encoding.'
    })
  }
  normalizedPath = normalizedPath.replace(/\/+/g, '/').toLowerCase()

  if (normalizedPath.startsWith('/api/')) {
    setHeader(event, 'Vary', 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Origin')

    const method = (event.method || 'GET').toUpperCase()
    const check = validateFetchMetadata(
      {
        'sec-fetch-site': getRequestHeader(event, 'sec-fetch-site'),
        'sec-fetch-mode': getRequestHeader(event, 'sec-fetch-mode'),
        'sec-fetch-dest': getRequestHeader(event, 'sec-fetch-dest')
      },
      method
    )

    if (!check.allowed) {
      throw createError({
        statusCode: 403,
        statusMessage: 'Forbidden: Cross-site API request rejected by Fetch Metadata isolation policy.'
      })
    }

    if (MUTATING_METHODS.has(method)) {
      const originHeader = getRequestHeader(event, 'origin')
      const hostHeader = getRequestHeader(event, 'host')
      if (originHeader) {
        let originHost = ''
        try {
          originHost = new URL(originHeader).host.toLowerCase()
        } catch {
          throw createError({
            statusCode: 403,
            statusMessage: 'Forbidden: Malformed Origin header.'
          })
        }
        if (!hostHeader || originHost !== hostHeader.trim().toLowerCase()) {
          throw createError({
            statusCode: 403,
            statusMessage: 'Forbidden: Cross-origin API request rejected.'
          })
        }
      }

      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        const contentType = (getRequestHeader(event, 'content-type') || '').trim().toLowerCase()
        if (!contentType.startsWith('application/json')) {
          throw createError({
            statusCode: 415,
            statusMessage: 'Unsupported Media Type: application/json is required.'
          })
        }

        const contentLengthRaw = getRequestHeader(event, 'content-length')
        if (contentLengthRaw !== undefined) {
          const contentLength = Number(contentLengthRaw)
          if (
            !Number.isFinite(contentLength) ||
            contentLength < 0 ||
            contentLength > MAX_API_BODY_BYTES
          ) {
            throw createError({
              statusCode: 413,
              statusMessage: 'Payload Too Large: Request body exceeds 256 KB limit.'
            })
          }
        }
      }
    }
  }
})
