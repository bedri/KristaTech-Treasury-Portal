import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'

const ROOT = path.resolve(import.meta.dirname, '..')

async function readProjectFile(relPath: string): Promise<string> {
  return fs.readFile(path.join(ROOT, relPath), 'utf8')
}

describe('Markup, Brand Identity, Accessibility & XSS Surface Audit', () => {
  it('ensures zero dangerous DOM XSS sinks across all Vue and TypeScript files', async () => {
    const filesToAudit = [
      'app/app.vue',
      'app/layouts/default.vue',
      'app/pages/index.vue',
      'app/pages/admin.vue',
      'app/composables/useI18n.ts',
      'app/utils/treasuryCrypto.ts',
      'server/api/quorum.ts',
      'server/api/proposals.ts',
      'server/utils/security.ts',
      'server/middleware/security.ts'
    ]

    const forbiddenPatterns = [
      /\bv-html\b/,
      /\.innerHTML\b/,
      /\.outerHTML\b/,
      /\binsertAdjacentHTML\b/,
      /\bdocument\.write\s*\(/,
      /\beval\s*\(/
    ]

    for (const rel of filesToAudit) {
      const content = await readProjectFile(rel)
      for (const regex of forbiddenPatterns) {
        assert.equal(
          regex.test(content),
          false,
          `Forbidden XSS sink pattern ${regex} found in ${rel}`
        )
      }
    }
  })

  it('verifies rel="noopener noreferrer" on all target="_blank" links and aria-hidden="true" on inline SVGs', async () => {
    const vueFiles = [
      'app/app.vue',
      'app/layouts/default.vue',
      'app/pages/index.vue',
      'app/pages/admin.vue'
    ]

    for (const rel of vueFiles) {
      const content = await readProjectFile(rel)

      // Check target="_blank"
      const blankTags = content.match(/<a\b[^>]*target="_blank"[^>]*>/g) || []
      for (const tag of blankTags) {
        assert.match(
          tag,
          /rel="noopener noreferrer"/,
          `Missing rel="noopener noreferrer" in ${rel}: ${tag}`
        )
      }

      // Check inline <svg tags
      const svgTags = content.match(/<svg\b[^>]*>/g) || []
      for (const svgTag of svgTags) {
        assert.match(
          svgTag,
          /aria-hidden="true"/,
          `Missing aria-hidden="true" on inline <svg> in ${rel}: ${svgTag}`
        )
      }
    }
  })

  it('verifies KristaTech original logo (#F5897C & #7695CD) and dominant brand CSS tokens', async () => {
    const logoSvg = await readProjectFile('public/logo.svg')
    const faviconSvg = await readProjectFile('public/favicon.svg')
    const mainCss = await readProjectFile('app/assets/css/main.css')
    const layoutVue = await readProjectFile('app/layouts/default.vue')
    const appVue = await readProjectFile('app/app.vue')

    assert.ok(logoSvg.includes('#F5897C'), 'public/logo.svg must contain Coral #F5897C')
    assert.ok(logoSvg.includes('#7695CD'), 'public/logo.svg must contain Cobalt #7695CD')
    assert.ok(faviconSvg.includes('#F5897C'), 'public/favicon.svg must contain Coral #F5897C')
    assert.ok(faviconSvg.includes('#7695CD'), 'public/favicon.svg must contain Cobalt #7695CD')

    assert.ok(mainCss.includes('#7695CD'), 'main.css must define #7695CD')
    assert.ok(mainCss.includes('#F5897C'), 'main.css must define #F5897C')
    assert.ok(mainCss.includes('scrollbar-gutter: stable'), 'main.css must reserve scrollbar-gutter')
    assert.ok(mainCss.includes('@supports not (accent-color: #7695CD)'), 'main.css must include @supports not accent-color fallback')
    assert.ok(mainCss.includes('@supports not (scrollbar-color: auto)'), 'main.css must include @supports not scrollbar-color fallback')

    assert.ok(layoutVue.includes('id="main-content"'), 'default.vue must include #main-content')
    assert.ok(layoutVue.includes('tabindex="-1"'), 'default.vue main landmark must be focusable')
    assert.ok(layoutVue.includes('href="#main-content"'), 'default.vue must include skip-link')
    assert.ok(appVue.includes("name: 'color-scheme'"), 'app.vue must declare color-scheme meta tag')

    // Ensure no gradient text classes or background-clip: text remain
    const indexVue = await readProjectFile('app/pages/index.vue')
    const adminVue = await readProjectFile('app/pages/admin.vue')
    for (const [name, src] of [
      ['main.css', mainCss],
      ['default.vue', layoutVue],
      ['index.vue', indexVue],
      ['admin.vue', adminVue]
    ] as const) {
      assert.equal(
        /brand-gradient-text|bg-clip-text|background-clip:\s*text/.test(src),
        false,
        `Text gradient must not be used in ${name}`
      )
    }
  })
})
