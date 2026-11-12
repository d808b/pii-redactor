/**
 * Independent adversarial audit of the PII redaction engine and its
 * `agent/pre-step` wiring.
 *
 * Rules for this file (see /tmp/pii-redactor-brief.md):
 *  - every fixture is synthetic and generated here at run time; no real
 *    ID / card / phone value is checked in,
 *  - the checksum implementations below are re-derived from the standards
 *    (ISO 7064 MOD 11-2 and Luhn) and never call the functions under test,
 *  - statistical tests use a fixed seed, so their numbers are reproducible,
 *  - "known false negative" tests assert the *desired* behaviour and are marked
 *    `todo`, so they document the gap without breaking `node --test`.
 *
 * Test names are grouped by the brief's audit checklist:
 *   A. checksum cross-validation      B. real-format hits
 *   C. boundary / over-redaction      D. measured false-positive rates (seeded)
 *   E. known false negatives (todo)   F. idempotency
 *   G. redactMessage contract         H. plugin wiring
 *   I. normalizeOptions fail-safe
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  DEFAULT_OPTIONS,
  PLACEHOLDERS,
  isMobile,
  isValidId15,
  isValidId18,
  normalizeOptions,
  passesLuhn,
  redactMessage,
  redactText,
} from '../lib/patterns.js'
import { apply } from '../index.js'

// ---------------------------------------------------------------------------
// Independent reference implementations (do not import module internals).
// ---------------------------------------------------------------------------

/**
 * ISO 7064 MOD 11-2 weights, derived from the standard's radix rule
 * `Wi = 2 ** (18 - i) mod 11` for i = 1..17, rather than copied from lib/.
 */
const REF_WEIGHTS = Array.from({ length: 17 }, (_, index) => (2 ** (17 - index)) % 11)

/**
 * ISO 7064 MOD 11-2 check character for a 17-digit base.
 * The standard maps the weighted-sum remainder r to (12 - r) mod 11, with the
 * value 10 written as `X`.
 */
function refIdCheckChar(base17) {
  const sum = [...base17].reduce((total, char, index) => total + Number(char) * REF_WEIGHTS[index], 0)
  const remainder = sum % 11
  return remainder === 2 ? 'X' : String((12 - remainder) % 11)
}

/** Append the standard check character to a 17-digit base. */
function refMakeId(base17) {
  return base17 + refIdCheckChar(base17)
}

/**
 * Luhn (ISO/IEC 7812 MOD 10), written from the definition: starting at the
 * rightmost digit (the check digit, never doubled), double every second digit
 * and subtract 9 when the product exceeds 9; the total must be a multiple of 10.
 */
function refLuhn(digits) {
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    const digit = digits.charCodeAt(index) - 48
    if (digit < 0 || digit > 9) return false
    sum += double ? (digit > 4 ? digit * 2 - 9 : digit * 2) : digit
    double = !double
  }
  return sum % 10 === 0
}

/** The unique digit that turns `prefix` into a Luhn-valid number. */
function refLuhnCheckDigit(prefix) {
  const hits = []
  for (let digit = 0; digit <= 9; digit += 1) {
    if (refLuhn(`${prefix}${digit}`)) hits.push(digit)
  }
  assert.equal(hits.length, 1, 'exactly one check digit must satisfy Luhn')
  return String(hits[0])
}

/** The one digit (0-9) that makes `prefix + digit` pass the reference Luhn. */
function refCard(prefix, length) {
  let body = prefix
  while (body.length < length - 1) body += String(Math.floor(rand() * 10))
  return body + refLuhnCheckDigit(body)
}

// Fixed-seed pseudo random generator (mulberry32) so every statistic below is
// reproducible across runs and machines.
function mulberry32(seed) {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

let rand = mulberry32(0x20261112)

/** Fresh deterministic digit string of the requested length. */
function digits(length) {
  let out = ''
  for (let index = 0; index < length; index += 1) out += String(Math.floor(rand() * 10))
  return out
}

/** Synthetic but structurally valid 18-digit ID (6-digit address + 8-digit birth + 3 digits). */
function makeId() {
  const province = ['11', '31', '44', '51', '65', '23', '37', '42', '53', '61'][Math.floor(rand() * 10)]
  const address = String(Math.floor(rand() * 10000)).padStart(4, '0')
  const year = 1950 + Math.floor(rand() * 56)
  const month = String(1 + Math.floor(rand() * 12)).padStart(2, '0')
  const day = String(1 + Math.floor(rand() * 28)).padStart(2, '0')
  const sequence = String(Math.floor(rand() * 1000)).padStart(3, '0')
  return refMakeId(`${province}${address}${year}${month}${day}${sequence}`)
}

/** Synthetic valid mainland mobile number. */
function makeMobile() {
  return `1${3 + Math.floor(rand() * 7)}${digits(9)}`
}

/** Any 11-19 digit ASCII run from the text, used to prove nothing leaked. */
function longDigitRuns(text) {
  return text.match(/\d{11,}/g) ?? []
}

const deepFreeze = (value) => {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const child of Object.values(value)) deepFreeze(child)
  }
  return value
}

// ---------------------------------------------------------------------------
// A. Independent checksum cross-validation.
// ---------------------------------------------------------------------------

test('A1: MOD 11-2 weight derivation matches the canonical sequence', () => {
  assert.deepEqual(REF_WEIGHTS, [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2])
})

test('A2: independent ISO 7064 MOD 11-2 agrees with isValidId18 on 400 generated IDs', () => {
  let withX = 0
  for (let index = 0; index < 400; index += 1) {
    const base = `${['11', '31', '44'][index % 3]}${digits(4)}19${String(60 + (index % 40)).padStart(2, '0')}${String(1 + (index % 12)).padStart(2, '0')}${String(1 + (index % 28)).padStart(2, '0')}${String(index % 1000).padStart(3, '0')}`
    const checkChar = refIdCheckChar(base)
    if (checkChar === 'X') withX += 1
    const full = base + checkChar
    assert.equal(isValidId18(full), true, 'reference-valid ID must be accepted')
    // Every other check character must be rejected by the plugin.
    for (const other of '0123456789X') {
      if (other === checkChar) continue
      assert.equal(isValidId18(base + other), false, 'wrong check character must be rejected')
    }
  }
  assert.ok(withX > 0, 'sample should include at least one X check character')
})

test('A3: independent Luhn agrees with passesLuhn on 2000 random digit strings', () => {
  for (let index = 0; index < 2000; index += 1) {
    const value = digits(15 + (index % 5))
    assert.equal(passesLuhn(value), refLuhn(value), 'Luhn implementations must agree')
  }
})

test('A4: every Luhn prefix has exactly one valid check digit (structural invariant)', () => {
  for (let index = 0; index < 200; index += 1) {
    const prefix = digits(15)
    const hits = [...'0123456789'].filter((digit) => passesLuhn(prefix + digit))
    assert.equal(hits.length, 1, 'a random prefix must have exactly one Luhn check digit')
  }
})

test('A5: X check character is accepted in both cases and counted as one value', () => {
  let xId = ''
  for (let index = 0; index < 5000 && xId === ''; index += 1) {
    const candidate = refMakeId(`11010119900307${String(index).padStart(3, '0')}`)
    if (candidate.endsWith('X')) xId = candidate
  }
  assert.ok(xId !== '', 'an X-suffixed valid ID must be constructible')
  assert.equal(isValidId18(xId), true)
  assert.equal(isValidId18(xId.toLowerCase()), true)
  assert.equal(redactText(`证件 ${xId}，`).text, '证件 [ID]，')
  assert.equal(redactText(`证件 ${xId.toLowerCase()}。`).text, '证件 [ID]。')
})

test('A6: isValidId18 rejects on independent grounds the reference also rejects', () => {
  const validBase = '11010119900307447'
  const valid = refMakeId(validBase)
  const flipped = `${valid.slice(0, 17)}${valid[17] === '9' ? '0' : String(Number(valid[17]) + 1)}`
  assert.equal(isValidId18(valid), true)
  assert.equal(isValidId18(flipped), false, 'checksum must be verified, not just the shape')
  assert.equal(isValidId18(refMakeId('11010119901307447')), false, 'month 13 must be rejected')
  assert.equal(isValidId18(refMakeId('11010119900230447')), false, 'Feb 30 must be rejected')
  assert.equal(isValidId18(refMakeId('99010119900307447')), false, 'unknown province must be rejected')
  assert.equal(isValidId18(refMakeId('11010120990307447')), false, 'future birth date must be rejected')
  assert.equal(isValidId18(refMakeId('11010117990307447')), false, 'birth year below 1800 must be rejected')
})

test('A7: legacy 15-digit validation is independent of the checksum path', () => {
  assert.equal(isValidId15('110101900307447'), true)
  assert.equal(isValidId15('110101901307447'), false)
  assert.equal(isValidId15('990101900307447'), false)
  assert.equal(isValidId15('11010190030744'), false)
})

// ---------------------------------------------------------------------------
// B. Real-format hits: structurally valid values must never be missed.
// ---------------------------------------------------------------------------

test('B1: 500 synthetic valid IDs are all replaced with [ID]', () => {
  const rng = mulberry32(11)
  const saved = rand
  rand = rng
  try {
    for (let index = 0; index < 500; index += 1) {
      const id = makeId()
      assert.equal(isValidId18(id), true, 'fixture must be reference-valid')
      const result = redactText(`身份证：${id}，请核对`)
      assert.equal(result.text, '身份证：[ID]，请核对')
      assert.deepEqual(result.counts, { id: 1, phone: 0, bank: 0 })
      assert.deepEqual(longDigitRuns(result.text), [], 'no digit run may survive')
    }
  } finally {
    rand = saved
  }
})

test('B2: 500 synthetic mobile numbers are all replaced with [PHONE]', () => {
  const saved = rand
  rand = mulberry32(12)
  try {
    for (let index = 0; index < 500; index += 1) {
      const phone = makeMobile()
      assert.equal(isMobile(phone), true, 'fixture must be a valid mobile')
      const result = redactText(`电话${phone}谢谢`)
      assert.equal(result.text, '电话[PHONE]谢谢')
      assert.deepEqual(result.counts, { id: 0, phone: 1, bank: 0 })
    }
  } finally {
    rand = saved
  }
})

test('B3: 16/17/19-digit Luhn-valid cards are all replaced with [BANK]', () => {
  const saved = rand
  rand = mulberry32(13)
  try {
    // 16, 17 and 19 are lengths that cannot also be an 18-digit ID.
    for (const length of [16, 17, 19]) {
      for (let index = 0; index < 100; index += 1) {
        const card = refCard('62', length)
        assert.equal(refLuhn(card), true)
        const result = redactText(`卡号 ${card} 到期 2030/01`)
        assert.equal(result.text, '卡号 [BANK] 到期 2030/01')
        assert.deepEqual(result.counts, { id: 0, phone: 0, bank: 1 })
      }
    }
  } finally {
    rand = saved
  }
})

test('B4: 18-digit Luhn-valid card with a non-province prefix is [BANK]', () => {
  // Prefix 17 cannot be an ID address prefix, so classification is unambiguous.
  const card = refCard('17', 18)
  assert.equal(refLuhn(card), true)
  assert.equal(redactText(card).text, '[BANK]')
})

test('B5: mixed kinds, Chinese punctuation, newlines and emoji all survive', () => {
  const id = refMakeId('11010119900307447')
  const card = refCard('622202123456789', 16)
  const phone = '13912345678'
  const text = `身份证号：${id}。\n电话：${phone}，卡号：${card}👌`
  const result = redactText(text)
  assert.equal(result.text, '身份证号：[ID]。\n电话：[PHONE]，卡号：[BANK]👌')
  assert.deepEqual(result.counts, { id: 1, phone: 1, bank: 1 })
  assert.equal(result.total, 3)
  assert.deepEqual(longDigitRuns(result.text), [])
})

test('B6: values at string start / end and glued to Chinese text are caught', () => {
  const id = refMakeId('11010119900307447')
  const phone = '13812345678'
  assert.equal(redactText(id).text, '[ID]')
  assert.equal(redactText(`${id}`).text, '[ID]')
  assert.equal(redactText(`电话${phone}`).text, '电话[PHONE]')
  assert.equal(redactText(`${phone}是我的号码`).text, '[PHONE]是我的号码')
})

test('B7: adjacent PII separated by space/comma/newline is fully replaced', () => {
  const id = refMakeId('11010119900307447')
  const phone = '13912345678'
  const card = refCard('622202123456789', 16)
  for (const separator of [' ', ',', '，', '\n', '\t', '|', ';']) {
    const text = `${id}${separator}${phone}${separator}${card}`
    const result = redactText(text)
    assert.equal(result.total, 3, `separator ${JSON.stringify(separator)} must keep all three separate tokens`)
    assert.deepEqual(longDigitRuns(result.text), [])
  }
})

test('B8: 86 / 0086 prefixed mobiles are replaced, and honoured the option', () => {
  const phone = '13812345678'
  assert.equal(redactText(`+86${phone}`).text, '[PHONE]')
  assert.equal(redactText(`0086${phone}`).text, '[PHONE]')
  assert.equal(redactText(`+86${phone}`, { allowCountryCode: false }).text, `+86${phone}`)
})

test('B9: legacy 15-digit ID is replaced only when explicitly enabled', () => {
  const legacy = '110101900307447'
  assert.equal(redactText(legacy).text, legacy)
  assert.equal(redactText(legacy, { allowLegacyId15: true }).text, '[ID]')
})

// ---------------------------------------------------------------------------
// C. Boundary / over-redaction on formats that must stay untouched.
// ---------------------------------------------------------------------------

test('C1: timestamps, epochs, IPs, ports and versions are left alone', () => {
  const samples = [
    '20261105203045', // 14-digit timestamp
    '1730000000000', // 13-digit epoch millis
    '2026110520', // 10-digit epoch seconds
    '173000000000', // 12-digit run
    '192.168.8.194:8080',
    '10.0.0.1',
    'v1.2.3 build 20261105',
    'port 65535, pid 1234567890',
  ]
  for (const sample of samples) {
    assert.equal(redactText(sample).text, sample, `must not touch ${sample}`)
  }
})

test('C2: 20+ digit runs and ASCII-alphanumeric tokens are never partially matched', () => {
  const samples = [
    `62220212345678901234`, // 20 digits: outside the 11-19 window
    `sha256:${'9'.repeat(20)}`,
    `abc13812345678def`,
    `IMG_20261105203045.jpg`,
  ]
  for (const sample of samples) {
    assert.equal(redactText(sample).text, sample, `must not touch ${sample}`)
  }
})

test('C2b: underscore is a boundary, so snake_case fields holding PII are redacted', () => {
  // lib/patterns.js documents `order_id_6222...` as *not* a card number, but the
  // boundary class only excludes [0-9A-Za-z]: the sample stays untouched because
  // its Luhn fails, not because of the underscore. A Luhn-valid value inside a
  // snake_case name IS redacted.
  assert.equal(redactText('order_id_6222021234567890').text, 'order_id_6222021234567890')
  assert.equal(redactText(`card_no_${refCard('622202123456789', 16)}`).text, 'card_no_[BANK]')
  assert.equal(redactText('field_13812345678').text, 'field_[PHONE]')
})

test('C3: UUIDs, hex, base64 and file paths are left alone', () => {
  const samples = [
    '550e8400-e29b-41d4-a716-446655440000',
    'deadbeef0123456789abcdef',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    '/var/log/pii/20261105-access.log',
    '123456789012345', // 15 digits: not an 11-digit mobile and below the 16-digit card window
  ]
  for (const sample of samples) {
    assert.equal(redactText(sample).text, sample, `must not touch ${sample}`)
  }
})

test('C4: the configured length window and requireLuhn switch behave', () => {
  const card = refCard('622202123456789', 16)
  assert.equal(redactText(card).text, '[BANK]')
  assert.equal(redactText(card, { requireLuhn: false }).text, '[BANK]')
  assert.equal(redactText(card, { minBankCardLength: 17 }).text, card)
  assert.equal(redactText(card, { maxBankCardLength: 15 }).text, card)
})

test('C5: placeholder text itself is inert (no digits, not re-matched)', () => {
  assert.deepEqual({ ...PLACEHOLDERS }, { id: '[ID]', phone: '[PHONE]', bank: '[BANK]' })
  for (const placeholder of Object.values(PLACEHOLDERS)) {
    assert.equal(/\d/.test(placeholder), false, 'placeholders must not contain digits')
  }
  assert.equal(redactText('[ID] [PHONE] [BANK]').text, '[ID] [PHONE] [BANK]')
})

// ---------------------------------------------------------------------------
// D. Measured false-positive rates (fixed seed, reproducible).
// ---------------------------------------------------------------------------

test('D1: random 16-19 digit numbers are [BANK] ~= 10% (Luhn theory)', (t) => {
  const saved = rand
  rand = mulberry32(0xbadd00d)
  let hits = 0
  const samples = 3000
  try {
    for (let index = 0; index < samples; index += 1) {
      if (redactText(digits(16 + (index % 4))).counts.bank === 1) hits += 1
    }
  } finally {
    rand = saved
  }
  const rate = hits / samples
  t.diagnostic(`random 16-19 digit BANK rate = ${(rate * 100).toFixed(2)}% (${hits}/${samples}); theory 10.00%`)
  assert.ok(rate > 0.075 && rate < 0.125, `expected ~1/10, got ${rate}`)
})

test('D2: random 18-digit numbers are almost never [ID] (strict check)', (t) => {
  const saved = rand
  rand = mulberry32(0x1d1d)
  let hits = 0
  const samples = 3000
  try {
    for (let index = 0; index < samples; index += 1) {
      if (redactText(digits(18), { strictIdChecksum: true }).counts.id === 1) hits += 1
    }
  } finally {
    rand = saved
  }
  t.diagnostic(`strict random 18-digit ID rate = ${hits}/${samples}; theory < 0.01% (date+province+check)`)
  assert.ok(hits <= 1, `random 18-digit strings must not look like IDs (got ${hits})`)
})

test('D2b: fallback mode keeps random 18-digit false positives negligible', (t) => {
  const saved = rand
  rand = mulberry32(0x1d1d)
  let hits = 0
  const samples = 3000
  try {
    for (let index = 0; index < samples; index += 1) {
      if (redactText(digits(18), { strictIdChecksum: false }).counts.id === 1) hits += 1
    }
  } finally {
    rand = saved
  }
  const rate = hits / samples
  t.diagnostic(`fallback random 18-digit ID rate = ${(rate * 100).toFixed(3)}% (${hits}/${samples}); theory ~0.035% (province 31% x year 3% x month 12% x day 31%)`)
  assert.ok(rate < 0.002, `fallback false-positive rate must stay under 0.2% (got ${rate})`)
})

test('D3: random 11-digit numbers are [PHONE] ~= 7% (1 + 3-9 prefix theory)', (t) => {
  const saved = rand
  rand = mulberry32(0xbeef)
  let hits = 0
  const samples = 3000
  try {
    for (let index = 0; index < samples; index += 1) {
      if (redactText(digits(11)).counts.phone === 1) hits += 1
    }
  } finally {
    rand = saved
  }
  const rate = hits / samples
  t.diagnostic(`random 11-digit PHONE rate = ${(rate * 100).toFixed(2)}% (${hits}/${samples}); theory 7.00%`)
  assert.ok(rate > 0.05 && rate < 0.09, `expected ~7%, got ${rate}`)
})

test('D4: plausible prefix/date values are [ID] ~100% with fallback, ~9% strict', (t) => {
  const saved = rand
  rand = mulberry32(0x5eed)
  let fallbackHits = 0
  let strictHits = 0
  const samples = 3000
  try {
    // Valid province prefix and valid birth date, but an arbitrary last digit:
    // the fallback accepts the shape, the strict check still demands ISO 7064.
    for (let index = 0; index < samples; index += 1) {
      const base = `110101${1980 + (index % 40)}${String(1 + (index % 12)).padStart(2, '0')}${String(1 + (index % 28)).padStart(2, '0')}${String(index % 1000).padStart(3, '0')}`
      const value = `${base}${Math.floor(rand() * 10)}`
      if (redactText(value, { strictIdChecksum: false }).counts.id === 1) fallbackHits += 1
      if (redactText(value, { strictIdChecksum: true }).counts.id === 1) strictHits += 1
    }
  } finally {
    rand = saved
  }
  const fallbackRate = fallbackHits / samples
  const strictRate = strictHits / samples
  t.diagnostic(`plausible 18-digit ID rate: fallback ${(fallbackRate * 100).toFixed(2)}%, strict ${(strictRate * 100).toFixed(2)}% (${strictHits}/${samples}); strict theory ~1/11 = 9.09%`)
  assert.ok(fallbackRate > 0.99, `fallback must catch the ID-shaped family (got ${fallbackRate})`)
  assert.ok(strictRate > 0.06 && strictRate < 0.13, `strict expected ~1/11, got ${strictRate}`)
})

// ---------------------------------------------------------------------------
// E. Regression coverage for the audit's known false negatives.
// E1/E2 were fixed in 0.1.1 (full-width folding + separator-tolerant matching);
// E3 stays documented as a structural limitation.
// ---------------------------------------------------------------------------

test('E1: full-width digits are folded and redacted', () => {
  // A full-width mobile number pasted from an IME must be redacted too.
  const fullWidth = '１３８１２３４５６７８'
  assert.equal(redactText(`电话${fullWidth}`).text, '电话[PHONE]')
  assert.equal(redactText(`电话＋８６１３８１２３４５６７８`).text, '电话[PHONE]')
})

test('E2: mobiles/cards written in groups are redacted', () => {
  assert.equal(redactText('电话 138 1234 5678').text, '电话 [PHONE]')
  assert.equal(redactText('电话 138-1234-5678').text, '电话 [PHONE]')
  const card = refCard('622202123456789', 16)
  const grouped = `${card.slice(0, 4)} ${card.slice(4, 8)} ${card.slice(8, 12)} ${card.slice(12)}`
  assert.equal(redactText(`卡号 ${grouped}`).text, '卡号 [BANK]')
})

test('E3: known FN - two PII values glued without a separator are skipped', { todo: 'glued runs exceed the candidate boundary' }, () => {
  const id = refMakeId('11010119900307447')
  const phone = '13812345678'
  assert.equal(redactText(`${id}${phone}`).text, '[ID][PHONE]')
})

// ---------------------------------------------------------------------------
// F. Idempotency.
// ---------------------------------------------------------------------------

test('F1: re-running redaction over redacted text is a no-op', () => {
  const text = `身份证 ${refMakeId('11010119900307447')} 电话 13812345678 卡号 ${refCard('622202123456789', 16)}`
  const once = redactText(text)
  assert.equal(once.total, 3)
  const twice = redactText(once.text)
  assert.equal(twice.text, once.text, 'second pass must not change the text')
  assert.equal(twice.total, 0, 'second pass must not count anything')
  const thrice = redactText(twice.text)
  assert.equal(thrice.text, once.text)
})

test('F2: idempotency holds when placeholders sit next to digits and punctuation', () => {
  const samples = [
    '电话：[PHONE]，卡号：[BANK]。',
    '编号 [ID]-2026 与 [PHONE] 相邻',
    '[ID][PHONE][BANK]',
  ]
  for (const sample of samples) {
    assert.equal(redactText(sample).text, sample)
    assert.equal(redactText(sample).total, 0)
  }
})

// ---------------------------------------------------------------------------
// G. redactMessage contract.
// ---------------------------------------------------------------------------

test('G1: redactMessage keeps identity, source, extra fields and non-text blocks', () => {
  const id = refMakeId('11010119900307447')
  const message = deepFreeze({
    id: 'm-audit-1',
    role: 'user',
    source: { kind: 'user', principal: 'p-1' },
    meta: { nested: ['x'] },
    content: [
      { type: 'text', text: `身份证 ${id}` },
      { type: 'image', attachment: { attachmentId: 'a-1' } },
    ],
  })
  const result = redactMessage(message, {})
  assert.equal(result.total, 1)
  assert.equal(result.message.id, 'm-audit-1')
  assert.deepEqual(result.message.source, { kind: 'user', principal: 'p-1' })
  assert.deepEqual(result.message.meta, { nested: ['x'] })
  assert.deepEqual(result.message.content[0], { type: 'text', text: '身份证 [ID]' })
  assert.equal(result.message.content[1], message.content[1], 'non-text block must be reused, not copied')
  assert.equal(result.message.content.length, 2)
})

test('G2: redactMessage reuses the message object when nothing matched', () => {
  const message = deepFreeze({ id: 'm-audit-2', source: { kind: 'user' }, content: [{ type: 'text', text: 'nothing here' }] })
  const result = redactMessage(message, {})
  assert.equal(result.message, message)
  assert.equal(result.total, 0)
})

test('G3: redactMessage tolerates malformed messages without throwing', () => {
  for (const message of [undefined, null, {}, { content: null }, { content: 'text' }, { content: [{ type: 'text', text: 42 }] }]) {
    const result = redactMessage(message, {})
    assert.equal(result.total, 0)
  }
})

// ---------------------------------------------------------------------------
// H. Plugin wiring (agent/pre-step).
// ---------------------------------------------------------------------------

/** Cordis-like context that records listeners and the warn log. */
function makeContext({ withLogger = true } = {}) {
  const listeners = new Map()
  const logs = []
  const ctx = {
    on(name, listener) {
      listeners.set(name, listener)
      return () => listeners.delete(name)
    },
    ...(withLogger ? { logger: { warn: (line) => logs.push(line) } } : {}),
  }
  return { ctx, listeners, logs }
}

/** One synthetic user message. */
function userMessage(id, text) {
  return { id, role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text }] }
}

async function dispatch(listeners, payload, decision) {
  let calls = 0
  const out = await listeners.get('agent/pre-step')(payload, async () => {
    calls += 1
    return decision
  })
  return { out, calls }
}

test('H1: registers exactly one agent/pre-step listener, and none when disabled', () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, {})
  assert.deepEqual([...listeners.keys()], ['agent/pre-step'])
  const disabled = makeContext()
  apply(disabled.ctx, { enabled: false })
  assert.equal(disabled.listeners.size, 0)
})

test('H2: rewrites user text and preserves every other decision field', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const id = refMakeId('11010119900307447')
  const decision = {
    kind: 'enter',
    messages: [userMessage('m-1', `身份证 ${id}，电话 13812345678`)],
    startsRequestSeries: true,
    custom: { a: 1 },
  }
  const { out, calls } = await dispatch(listeners, { turn: 4, step: 2 }, decision)
  assert.equal(calls, 1, 'next() must be called exactly once')
  assert.notEqual(out, decision, 'a changed decision must be a new object')
  assert.equal(out.kind, 'enter')
  assert.equal(out.startsRequestSeries, true, 'startsRequestSeries must survive')
  assert.deepEqual(out.custom, { a: 1 }, 'unknown decision fields must survive')
  assert.equal(out.messages[0].id, 'm-1')
  assert.equal(out.messages[0].content[0].text, '身份证 [ID]，电话 [PHONE]')
  assert.equal(logs.length, 1)
  assert.match(logs[0], /已拦截并替换 2 条敏感信息/)
  assert.match(logs[0], /turn=4 step=2/)
  assert.deepEqual(longDigitRuns(logs[0]), [], 'the warn line must never contain an original value')
})

test('H3: the warning uses counts only, for every redaction kind', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const id = refMakeId('11010119900307447')
  const card = refCard('622202123456789', 16)
  const decision = { kind: 'enter', messages: [userMessage('m-2', `${id} 13912345678 ${card}`)] }
  const { out } = await dispatch(listeners, undefined, decision)
  assert.deepEqual(longDigitRuns(out.messages[0].content[0].text), [])
  assert.equal(logs.length, 1)
  assert.match(logs[0], /身份证 1 \/ 手机号 1 \/ 银行卡 1/)
  assert.deepEqual(longDigitRuns(logs[0]), [])
  assert.match(logs[0], /\[pii-redactor\]/, 'log prefix must stay greppable')
})

test('H4: reject / non-enter / malformed decisions pass through by identity', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  for (const decision of [
    { kind: 'reject' },
    { kind: 'reject', reason: 'denied' },
    null,
    undefined,
    { kind: 'enter' },
    { kind: 'enter', messages: 'not-an-array' },
  ]) {
    const { out } = await dispatch(listeners, {}, decision)
    assert.equal(out, decision, 'untouched decisions must be returned by identity')
  }
  assert.equal(logs.length, 0, 'nothing to log when nothing was redacted')
})

test('H5: a deep-frozen decision and its messages are accepted', async () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, {})
  const id = refMakeId('11010119900307447')
  const decision = deepFreeze({ kind: 'enter', messages: [deepFreeze(userMessage('m-frozen', `id ${id}`))], startsRequestSeries: false })
  const { out } = await dispatch(listeners, { turn: 1, step: 1 }, decision)
  assert.equal(out.messages[0].content[0].text, 'id [ID]')
  assert.equal(decision.messages[0].content[0].text, `id ${id}`, 'input must not be mutated')
})

test('H6: injected runtime context is skipped by default and redacted on request', async () => {
  const id = refMakeId('11010119900307447')
  const injected = { id: 'ctx-1', role: 'user', source: { kind: 'runtime-context' }, content: [{ type: 'text', text: `recall ${id}` }] }
  const on = makeContext()
  apply(on.ctx, {})
  const { out: untouched } = await dispatch(on.listeners, {}, { kind: 'enter', messages: [injected] })
  assert.equal(untouched.messages[0].content[0].text, `recall ${id}`, 'runtime context is out of scope by default')
  assert.equal(on.logs.length, 0)

  const forced = makeContext()
  apply(forced.ctx, { redactInjectedContext: true })
  const { out: redacted } = await dispatch(forced.listeners, {}, { kind: 'enter', messages: [injected] })
  assert.equal(redacted.messages[0].content[0].text, 'recall [ID]')
})

test('H7: a non-user injected message is left alone by default', async () => {
  const id = refMakeId('11010119900307447')
  const scheduled = { id: 'sch-1', role: 'user', source: { kind: 'schedule' }, content: [{ type: 'text', text: id }] }
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const { out } = await dispatch(listeners, {}, { kind: 'enter', messages: [scheduled] })
  assert.equal(out.messages[0].content[0].text, id)
  assert.equal(logs.length, 0)
})

test('H8: engine failure fails open but never silently and never leaks the value', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const hostile = {
    id: 'm-hostile',
    role: 'user',
    source: { kind: 'user' },
    get content() {
      throw new Error('boom')
    },
  }
  const decision = { kind: 'enter', messages: [hostile] }
  const { out } = await dispatch(listeners, { turn: 2, step: 3 }, decision)
  assert.equal(out, decision, 'fail-open keeps the original decision')
  assert.equal(logs.length, 1, 'fail-open must warn, not be silent')
  assert.match(logs[0], /脱敏失败/)
  assert.match(logs[0], /按原文放行/)
  assert.deepEqual(longDigitRuns(logs[0]), [], 'the failure log must not echo a value')
})

test('H9: a missing logger falls back to console.warn and still redacts', async (t) => {
  const { ctx, listeners } = makeContext({ withLogger: false })
  apply(ctx, {})
  const id = refMakeId('11010119900307447')
  const captured = []
  const original = console.warn
  console.warn = (...args) => captured.push(args.join(' '))
  try {
    const { out } = await dispatch(listeners, {}, { kind: 'enter', messages: [userMessage('m-nolog', `id ${id}`)] })
    assert.equal(out.messages[0].content[0].text, 'id [ID]')
  } finally {
    console.warn = original
  }
  t.diagnostic(`console.warn fallback lines = ${captured.length}`)
  assert.ok(captured.length >= 1)
  assert.deepEqual(longDigitRuns(captured.join('\n')), [])
})

test('H10: upstream next() errors are not swallowed (no fail-open on host errors)', async () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, {})
  await assert.rejects(
    () => listeners.get('agent/pre-step')({}, async () => {
      throw new Error('upstream')
    }),
    /upstream/,
  )
})

// ---------------------------------------------------------------------------
// I. normalizeOptions fail-safe (cannot silently disable redaction).
// ---------------------------------------------------------------------------

test('I1: type mismatches and unknown keys keep redaction ON', () => {
  const cases = [
    undefined,
    null,
    'false',
    true,
    42,
    { enable: false }, // typo
    { enabled: 'false' }, // string instead of boolean
    { enabled: 0 },
    { redactIdCard: 0 },
    { redactPhone: 'false' },
    { redactBankCard: 'false' },
    { requireLuhn: 'true' },
    { minBankCardLength: '16' },
    { minBankCardLength: Number.NaN },
    { maxBankCardLength: null },
  ]
  for (const config of cases) {
    const options = normalizeOptions(config)
    assert.equal(options.enabled, true, `config ${JSON.stringify(config)} must not disable the plugin`)
    assert.equal(options.redactIdCard, true)
    assert.equal(options.redactPhone, true)
    assert.equal(options.redactBankCard, true)
    assert.equal(options.requireLuhn, true)
    assert.equal(options.minBankCardLength, 16)
  }
})

test('I2: well-typed user intent is still honoured', () => {
  assert.equal(normalizeOptions({ enabled: false }).enabled, false)
  assert.equal(normalizeOptions({ allowLegacyId15: true }).allowLegacyId15, true)
  assert.equal(normalizeOptions({ redactInjectedContext: true }).redactInjectedContext, true)
  assert.equal(normalizeOptions({ minBankCardLength: 18 }).minBankCardLength, 18)
})

test('I3: null prototype keys and unknown keys cannot leak into the effective options', () => {
  const polluted = JSON.parse('{"__proto__":{"enabled":false},"constructor":{"x":1},"toString":1}')
  const options = normalizeOptions(polluted)
  assert.equal(options.enabled, true)
  assert.equal(Object.keys(options).sort().join(','), Object.keys(DEFAULT_OPTIONS).sort().join(','))
})

test('I4: the plugin honours the fail-safe parse (a string "false" cannot switch it off)', async () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, { enabled: 'false' })
  const id = refMakeId('11010119900307447')
  const { out } = await dispatch(listeners, {}, { kind: 'enter', messages: [userMessage('m-typo', id)] })
  assert.equal(out.messages[0].content[0].text, '[ID]')
})
