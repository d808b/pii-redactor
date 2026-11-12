import assert from 'node:assert/strict'
import test from 'node:test'

import {
  isValidId15,
  isValidId18,
  isMobile,
  passesLuhn,
  redactMessage,
  redactText,
} from '../lib/patterns.js'

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK_CHARS = '10X98765432'

/** Append the ISO 7064 MOD 11-2 check character to 17 digits. */
function withCheckDigit(base17) {
  let sum = 0
  for (let index = 0; index < 17; index += 1) sum += Number(base17[index]) * ID_WEIGHTS[index]
  return base17 + ID_CHECK_CHARS[sum % 11]
}

/** Append the Luhn check digit to a digit prefix. */
function withLuhnDigit(prefix) {
  for (let digit = 0; digit <= 9; digit += 1) {
    const candidate = `${prefix}${digit}`
    if (passesLuhn(candidate)) return candidate
  }
  throw new Error(`no Luhn digit for ${prefix}`)
}

/** Find a structurally valid ID whose check character is `X`. */
function idEndingInX() {
  for (let sequence = 0; sequence <= 999; sequence += 1) {
    const base = `11010119900307${String(sequence).padStart(3, '0')}`
    if (withCheckDigit(base).endsWith('X')) return withCheckDigit(base)
  }
  throw new Error('no X-suffixed ID found')
}

const VALID_ID = withCheckDigit('11010119900307447')
const VALID_ID_X = idEndingInX()
const VALID_CARD = withLuhnDigit('622202123456789')

test('the fixtures themselves are structurally valid', () => {
  assert.equal(isValidId18(VALID_ID), true)
  assert.equal(isValidId18(VALID_ID_X), true)
  assert.equal(VALID_ID_X.endsWith('X'), true)
  assert.equal(passesLuhn(VALID_CARD), true)
})

test('redacts a valid 18-digit ID card number', () => {
  const result = redactText(`身份证号：${VALID_ID}，请核对`)
  assert.equal(result.text, '身份证号：[ID]，请核对')
  assert.deepEqual(result.counts, { id: 1, phone: 0, bank: 0 })
  assert.equal(result.total, 1)
})

test('redacts an X-suffixed ID in both cases', () => {
  assert.equal(redactText(`A ${VALID_ID_X}`).text, 'A [ID]')
  assert.equal(redactText(`A ${VALID_ID_X.toLowerCase()}`).text, 'A [ID]')
})

test('flags an ID-shaped value whose check character fails, unless strict mode is on', () => {
  const digit = /\d/.test(VALID_ID[17]) ? Number(VALID_ID[17]) : 0
  const wrong = `${VALID_ID.slice(0, 17)}${(digit + 1) % 10}`
  assert.equal(redactText(wrong).text, '[ID]', 'default fallback must catch a mis-copied ID')
  assert.equal(
    redactText(wrong, { strictIdChecksum: true }).text.includes('[ID]'),
    false,
    'strict mode must keep demanding the check character',
  )
})

test('rejects impossible birth dates and unknown address prefixes', () => {
  assert.equal(isValidId18(withCheckDigit('11010119901307447')), false)
  assert.equal(isValidId18(withCheckDigit('11010119900230447')), false)
  assert.equal(isValidId18(withCheckDigit('99010119900307447')), false)
  assert.equal(isValidId18(withCheckDigit('11010120990307447')), false)
})

test('redacts mainland mobile numbers', () => {
  const result = redactText('联系我 13812345678 谢谢')
  assert.equal(result.text, '联系我 [PHONE] 谢谢')
  assert.deepEqual(result.counts, { id: 0, phone: 1, bank: 0 })
})

test('rejects 10/12-digit runs and invalid mobile prefixes', () => {
  assert.equal(redactText('1381234567').text, '1381234567')
  assert.equal(redactText('138123456789').text, '138123456789')
  assert.equal(redactText('12812345678').text, '12812345678')
  assert.equal(isMobile('12812345678'), false)
})

test('redacts 86-prefixed numbers only when allowCountryCode is on', () => {
  assert.equal(redactText('+8613812345678').text, '[PHONE]')
  assert.equal(redactText('008613812345678').text, '[PHONE]')
  assert.equal(redactText('+8613812345678', { allowCountryCode: false }).text, '+8613812345678')
})

test('never matches a phone number embedded in a longer digit run', () => {
  const result = redactText('20261381234567890')
  assert.equal(result.text.includes('[PHONE]'), false)
})

test('redacts a Luhn-valid bank card and counts it', () => {
  const result = redactText(`卡号 ${VALID_CARD} 到期 2030/01`)
  assert.equal(result.text, '卡号 [BANK] 到期 2030/01')
  assert.deepEqual(result.counts, { id: 0, phone: 0, bank: 1 })
})

test('keeps a 16-digit run that fails Luhn unless requireLuhn is off', () => {
  let bad = ''
  for (let digit = 0; digit <= 9; digit += 1) {
    const candidate = `622202123456789${digit}`
    if (!passesLuhn(candidate) && !isValidId18(candidate)) {
      bad = candidate
      break
    }
  }
  assert.notEqual(bad, '')
  assert.equal(redactText(bad).text, bad)
  assert.equal(redactText(bad, { requireLuhn: false }).text, '[BANK]')
})

test('honours the bank card length window', () => {
  assert.equal(redactText(VALID_CARD, { maxBankCardLength: 15 }).text, VALID_CARD)
  assert.equal(redactText(VALID_CARD, { minBankCardLength: 17 }).text, VALID_CARD)
})

test('redacts mixed kinds in one text and reports each count', () => {
  const result = redactText(`ID ${VALID_ID} / TEL 13912345678 / CARD ${VALID_CARD}`)
  assert.equal(result.text, 'ID [ID] / TEL [PHONE] / CARD [BANK]')
  assert.deepEqual(result.counts, { id: 1, phone: 1, bank: 1 })
  assert.equal(result.total, 3)
})

test('leaves unrelated digits and dotted versions alone', () => {
  const text = 'order 20261105203045, ip 10.0.0.1, port 8080, build 1.2.3.4'
  assert.equal(redactText(text).text, text)
})

test('ignores 20-digit runs entirely', () => {
  const text = 'tracking 62220212345678901234 end'
  assert.equal(redactText(text).text, text)
})

test('matches the retired 15-digit format only when enabled', () => {
  const legacy = '110101900307447'
  assert.equal(isValidId15(legacy), true)
  assert.equal(redactText(legacy).text, legacy)
  assert.equal(redactText(legacy, { allowLegacyId15: true }).text, '[ID]')
})

test('redactMessage keeps identity, source, and non-text blocks', () => {
  const message = {
    id: 'm-1',
    role: 'user',
    source: { kind: 'user' },
    content: [
      { type: 'text', text: `tel ${'13812345678'}` },
      { type: 'image', attachment: { attachmentId: 'a-1' } },
    ],
  }
  const frozen = JSON.stringify(message)
  const result = redactMessage(message, {})
  assert.equal(result.total, 1)
  assert.equal(result.message.id, 'm-1')
  assert.equal(result.message.source.kind, 'user')
  assert.deepEqual(result.message.content[0], { type: 'text', text: 'tel [PHONE]' })
  assert.deepEqual(result.message.content[1], message.content[1])
  assert.equal(JSON.stringify(message), frozen, 'input message must not be mutated')
})

test('redactMessage returns the same reference when nothing matched', () => {
  const message = { id: 'm-2', source: { kind: 'user' }, content: [{ type: 'text', text: 'hello' }] }
  const result = redactMessage(message, {})
  assert.equal(result.message, message)
  assert.equal(result.total, 0)
})

test('folds full-width IME input and keeps the caller characters intact', () => {
  const fullWidthPhone = '１３８１２３４５６７８'
  const result = redactText(`电话${fullWidthPhone}，编号 １２３`)
  assert.equal(result.text, '电话[PHONE]，编号 １２３')
  assert.equal(result.counts.phone, 1)
  assert.equal(redactText(`＋８６１３８１２３４５６７８`).text, '[PHONE]')
})

test('redacts grouped mobiles and Luhn-valid grouped cards', () => {
  assert.equal(redactText('电话 138 1234 5678').text, '电话 [PHONE]')
  assert.equal(redactText('电话 138-1234-5678').text, '电话 [PHONE]')
  const grouped = `${VALID_CARD.slice(0, 4)} ${VALID_CARD.slice(4, 8)} ${VALID_CARD.slice(8, 12)} ${VALID_CARD.slice(12)}`
  assert.equal(redactText(`卡号 ${grouped}`).text, '卡号 [BANK]')
})

test('does not group a spaced date into a bank card', () => {
  assert.equal(redactText('日期 2026 11 05').text, '日期 2026 11 05')
  assert.equal(redactText('日期 2026-11-05').text, '日期 2026-11-05')
})

test('fallback still rejects impossible months and unknown address prefixes', () => {
  const badMonth = '11010119901307447'
  const badPrefix = '99010119900307447'
  for (const base of [badMonth, badPrefix]) {
    for (let digit = 0; digit <= 9; digit += 1) {
      const value = `${base}${digit}`
      assert.equal(redactText(value).text.includes('[ID]'), false, `must not flag ${value.length}-digit non-ID`)
    }
  }
})

test('fallback flags an ID-shaped value with a future birth date (documented widening)', () => {
  // A real card can never carry a future birth date, so this shape is either
  // forced or fabricated; the fallback treats it as an ID anyway.
  const future = '11010120991231447'
  const flagged = Array.from({ length: 10 }, (_, digit) => redactText(`${future}${digit}`).text)
  assert.ok(flagged.some((text) => text === '[ID]'), 'at least one future-dated shape must be flagged')
  const strict = Array.from({ length: 10 }, (_, digit) => redactText(`${future}${digit}`, { strictIdChecksum: true }).text)
  assert.equal(strict.includes('[ID]'), false, 'strict mode must not flag future dates')
})
