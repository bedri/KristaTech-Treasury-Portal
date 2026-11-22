import { defineEventHandler, getRequestHeader, setHeader, createError } from 'h3'
import { SECURITY_HEADERS, validateFetchMetadata } from '../utils/security'

export default defineEventHandler((event) => {
  // Apply defense-in-depth HTTP security headers (modern-web-guidance: security §1.4, §3.4, §3.5, §3.7)
  for (const [headerName, headerValue] of Object.entries(SECURITY_HEADERS)) {
    setHeader(event, headerName, headerValue)
  }

  const reqPath = event.path || ''
  if (reqPath.startsWith('/api/')) {
    setHeader(event, 'Vary', 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site')

    const check = validateFetchMetadata(
      {
        'sec-fetch-site': getRequestHeader(event, 'sec-fetch-site'),
        'sec-fetch-mode': getRequestHeader(event, 'sec-fetch-mode'),
        'sec-fetch-dest': getRequestHeader(event, 'sec-fetch-dest')
      },
      event.method
    )

    if (!check.allowed) {
      throw createError({
        statusCode: 403,
        statusMessage: 'Forbidden: Cross-site API request rejected by Fetch Metadata isolation policy.'
      })
    }
  }
})
