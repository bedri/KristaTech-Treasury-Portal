import crypto from 'node:crypto'
import { removeResponseHeader, setResponseHeader } from 'h3'
import { buildHtmlCsp } from '../utils/security'

function injectNonceIntoScripts(chunks: string[], nonce: string): void {
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i]
    if (!chunk || !chunk.includes('<script')) continue
    chunks[i] = chunk.replace(/<script\b([^>]*)>/gi, (full, attrs: string) => {
      if (/\bnonce\s*=/i.test(attrs)) return full
      if (/\btype\s*=\s*["']application\/json["']/i.test(attrs)) return full
      return `<script nonce="${nonce}"${attrs}>`
    })
  }
}

export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook('render:html', (html, { event }) => {
    const nonce = crypto.randomBytes(16).toString('base64')
    if (event?.context) {
      event.context.cspNonce = nonce
    }
    injectNonceIntoScripts(html.head, nonce)
    injectNonceIntoScripts(html.bodyPrepend, nonce)
    injectNonceIntoScripts(html.bodyAppend, nonce)
  })

  nitroApp.hooks.hook('render:response', (response, { event }) => {
    if (response.headers) {
      delete response.headers['x-powered-by']
      delete response.headers['X-Powered-By']
      const nonce = event?.context?.cspNonce
      if (typeof nonce === 'string' && nonce) {
        response.headers['Content-Security-Policy'] = buildHtmlCsp(
          nonce,
          process.env.NODE_ENV !== 'production'
        )
      }
    }
  })

  nitroApp.hooks.hook('beforeResponse', (event) => {
    removeResponseHeader(event, 'x-powered-by')
    const nonce = event?.context?.cspNonce
    if (typeof nonce === 'string' && nonce) {
      setResponseHeader(
        event,
        'Content-Security-Policy',
        buildHtmlCsp(nonce, process.env.NODE_ENV !== 'production')
      )
    }
  })
})
