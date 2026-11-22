import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  SUPPORTED_LANGUAGES,
  translations,
  sanitizeLocale,
  sanitizeTheme,
  translate
} from '../app/composables/useI18n.ts'

describe('useI18n — Multi-language Dictionary Parity & Prototype-Pollution Safety', () => {
  it('supports all 10 institutional languages and freezes dictionaries', () => {
    assert.equal(SUPPORTED_LANGUAGES.length, 10)
    assert.equal(Object.isFrozen(SUPPORTED_LANGUAGES), true)
    assert.equal(Object.isFrozen(translations), true)
    for (const lang of SUPPORTED_LANGUAGES) {
      assert.equal(Object.isFrozen(translations[lang.code]), true)
    }
  })

  it('maintains 100% key parity and non-empty strings across all 10 languages', () => {
    const baseKeys = Object.keys(translations.tr).sort()
    assert.ok(baseKeys.length >= 100)

    for (const lang of SUPPORTED_LANGUAGES) {
      const dict = translations[lang.code]
      const keys = Object.keys(dict).sort()
      assert.deepEqual(keys, baseKeys, `Key mismatch in locale "${lang.code}"`)
      for (const k of keys) {
        const val = dict[k]
        assert.equal(typeof val, 'string', `Missing string for ${lang.code}.${k}`)
        assert.ok(val!.trim().length > 0, `Empty translation for ${lang.code}.${k}`)
      }
    }
  })

  it('sanitizes locale and theme inputs and blocks prototype-pollution keys', () => {
    assert.equal(sanitizeLocale('EN-US'), 'en')
    assert.equal(sanitizeLocale('de'), 'de')
    assert.equal(sanitizeLocale('unknown_locale', 'tr'), 'tr')
    assert.equal(sanitizeLocale(null, 'en'), 'en')

    assert.equal(sanitizeTheme('light'), 'light')
    assert.equal(sanitizeTheme('dark'), 'dark')
    assert.equal(sanitizeTheme('invalid', 'dark'), 'dark')

    assert.equal(translate('tr', 'badgeTreasury'), 'HAZİNE')
    assert.equal(translate('en', 'badgeTreasury'), 'TREASURY')
    assert.equal(translate('ja', 'badgeTreasury'), 'トレジャリー')
    assert.equal(translate('en', '__proto__'), '__proto__')
    assert.equal(translate('en', 'constructor'), 'constructor')
    assert.equal(translate('en', 'prototype'), 'prototype')
  })
})
