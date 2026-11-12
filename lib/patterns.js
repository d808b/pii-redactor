/**
 * Pure redaction engine for mainland-China PII.
 *
 * Zero dependencies and zero DSH imports, so it can be unit-tested with plain
 * `node --test` and reused outside the plugin (for example by a log scrubber).
 *
 * Detection order per candidate token is fixed: 18/15-digit ID card, then
 * mobile number (with optional 86/0086 country code), then bank card. The ID
 * branch runs a real ISO 7064 MOD 11-2 checksum plus province and birth-date
 * validation, and the bank branch runs Luhn, which is what makes these rules
 * "high precision" rather than plain digit-length guesses.
 *
 * Two input shapes are covered: contiguous digit tokens (11-19 digits, with an
 * optional trailing `X` for ID cards) and grouped tokens (`138 1234 5678`,
 * `6222-0212-3456-7890`) whose groups are each at least three digits.
 * Full-width ASCII forms (Chinese IME output) are folded to ASCII for scanning
 * while the returned text keeps the caller's original characters.
 *
 * Known non-goals: separators are only space / no-break space / hyphen;
 * semantic PII (names, addresses) never matches; two adjacent PII values with
 * nothing between them collapse into one over-long digit run and are skipped.
 *
 * @module @local/dsh-pii-redactor/patterns
 */

/** Placeholder text that replaces one redacted value. */
export const PLACEHOLDERS = Object.freeze({
  id: '[ID]',
  phone: '[PHONE]',
  bank: '[BANK]',
})

/** Two-digit address prefixes that a real mainland ID card can carry. */
const PROVINCE_PREFIXES = new Set([
  '11', '12', '13', '14', '15',
  '21', '22', '23',
  '31', '32', '33', '34', '35', '36', '37',
  '41', '42', '43', '44', '45', '46',
  '50', '51', '52', '53', '54',
  '61', '62', '63', '64', '65',
  '71', '81', '82', '91',
])

/** ISO 7064 MOD 11-2 position weights for the first 17 digits of an ID number. */
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]

/** Check-character table indexed by `weighted sum mod 11`. */
const ID_CHECK_CHARS = '10X98765432'

/** Current mainland mobile numbers: 11 digits, `1` + `3-9` + 9 digits. */
const MOBILE_RE = /^1[3-9]\d{9}$/

/**
 * One contiguous candidate: 11-19 ASCII digits plus an optional trailing `X`
 * (an 18-digit ID number may end in `X`), optionally led by `+`, and not glued
 * to a longer ASCII alphanumeric token. Chinese punctuation, whitespace, and
 * `_` are valid boundaries.
 */
const CANDIDATE_SOURCE = '(?<![0-9A-Za-z])(\\+?\\d{11,19}[Xx]?)(?![0-9A-Za-z])'

/**
 * One grouped candidate: at least two digit groups joined by a single space,
 * no-break space, or hyphen. Grouped values are compacted before validation,
 * so `6222 0212 3456 7890` is one 16-digit candidate.
 */
const GROUPED_SOURCE = '(?<![0-9A-Za-z])(\\d{1,6}(?:[- \\u00A0]\\d{1,6})+)(?![0-9A-Za-z])'

/** Separators allowed inside a grouped candidate. */
const GROUP_SEPARATOR_RE = /[- \u00A0]/g

/** Width forms that fold 1:1 to ASCII: digits, `+`, `-`, and the ideographic space. */
const WIDE_FORMS_RE = /[\u3000\uFF0B\uFF0D\uFF10-\uFF19]/g

/** Default options; a user row overrides individual keys. */
export const DEFAULT_OPTIONS = Object.freeze({
  /** Master switch: false leaves every message untouched. */
  enabled: true,
  /** Replace 18-digit (and optionally 15-digit) ID card numbers. */
  redactIdCard: true,
  /** Replace 11-digit mainland mobile numbers. */
  redactPhone: true,
  /** Replace 16-19 digit bank card numbers. */
  redactBankCard: true,
  /** Also match the retired 15-digit ID format (no checksum available). */
  allowLegacyId15: false,
  /**
   * Require the ISO 7064 check character before calling an 18-digit value an
   * ID. The default (false) also redacts ID-shaped values whose province and
   * birth-date fields are plausible but whose check character fails, which is
   * the common shape of a mis-copied or deliberately edited ID.
   */
  strictIdChecksum: false,
  /** Also match `86`/`0086` prefixed mobile numbers. */
  allowCountryCode: true,
  /** Require a valid Luhn checksum before calling a digit run a bank card. */
  requireLuhn: true,
  /** Shortest accepted bank card length. */
  minBankCardLength: 16,
  /** Longest accepted bank card length. */
  maxBankCardLength: 19,
  /**
   * Also redact non-human messages injected into the step (memory recall,
   * provider context). The agent loop drops rewrites of its own
   * `runtime-context` snapshot, so that one kind can never be redacted here.
   */
  redactInjectedContext: false,
  /**
   * On an unexpected engine error: false sends the original messages and warns;
   * true rejects the step so nothing unredacted reaches the model.
   */
  failClosed: false,
})

/**
 * Merge a raw Loader config row onto {@link DEFAULT_OPTIONS}.
 * Unknown keys are dropped and type-mismatched values keep the default so a
 * typo can never silently disable (or crash) redaction.
 * @param {unknown} config - raw `config` block of the Loader row.
 * @returns {typeof DEFAULT_OPTIONS} effective options.
 */
export function normalizeOptions(config) {
  const source = config !== null && typeof config === 'object' ? config : {}
  const options = { ...DEFAULT_OPTIONS }
  for (const key of Object.keys(DEFAULT_OPTIONS)) {
    const value = Reflect.get(source, key)
    if (value === undefined) continue
    if (typeof value !== typeof DEFAULT_OPTIONS[key]) continue
    if (typeof value === 'number' && !Number.isFinite(value)) continue
    options[key] = value
  }
  return options
}

/**
 * Whether a year/month/day triple names a real calendar day.
 * @param {number} year - four-digit year.
 * @param {number} month - 1-12.
 * @param {number} day - 1-31.
 * @returns {boolean} true when the date exists.
 */
function isRealDate(year, month, day) {
  if (month < 1 || month > 12 || day < 1) return false
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const monthLength = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day <= monthLength[month - 1]
}

/**
 * Whether a birth date sits in the future, which no issued ID can do.
 * The comparison uses the Asia/Shanghai (UTC+8) calendar day regardless of the
 * host's own time zone.
 * @param {number} year - four-digit year.
 * @param {number} month - 1-12.
 * @param {number} day - 1-31.
 * @returns {boolean} true when the date is after today in Asia/Shanghai.
 */
function isFutureDate(year, month, day) {
  const beijing = new Date(Date.now() + 8 * 60 * 60 * 1000)
  const today = [beijing.getUTCFullYear(), beijing.getUTCMonth() + 1, beijing.getUTCDate()]
  const candidate = [year, month, day]
  for (let index = 0; index < 3; index += 1) {
    if (candidate[index] !== today[index]) return candidate[index] > today[index]
  }
  return false
}

/**
 * Validate an 18-character mainland ID card number.
 * Checks digits, address prefix, calendrical birth date, not-in-the-future
 * birth date, and the ISO 7064 MOD 11-2 check character (`X` accepted in
 * either case).
 * @param {string} id - candidate with no separators.
 * @returns {boolean} true when the value is a structurally valid ID number.
 */
export function isValidId18(id) {
  if (typeof id !== 'string' || !/^\d{17}[\dXx]$/.test(id)) return false
  if (!PROVINCE_PREFIXES.has(id.slice(0, 2))) return false
  const year = Number(id.slice(6, 10))
  const month = Number(id.slice(10, 12))
  const day = Number(id.slice(12, 14))
  if (year < 1800 || year > 2099) return false
  if (!isRealDate(year, month, day)) return false
  if (isFutureDate(year, month, day)) return false
  let sum = 0
  for (let index = 0; index < 17; index += 1) {
    sum += (id.charCodeAt(index) - 48) * ID_WEIGHTS[index]
  }
  return ID_CHECK_CHARS[sum % 11] === id.charAt(17).toUpperCase()
}

/**
 * Structural ID guess used when `strictIdChecksum` is off.
 *
 * Accepts an 18-character value with a valid address prefix and a `YYYYMMDD`
 * birth date whose fields are merely in range: the check character, the
 * leap-year test, and the future-date test are skipped on purpose. A value
 * shaped like an ID that fails those tests is far more likely to be a forced
 * or mis-copied ID than an innocent number, so the safe direction for
 * redaction is to flag it.
 * @param {string} id - candidate with no separators.
 * @returns {boolean} true when the value is structurally ID-shaped.
 */
export function looksLikeId18(id) {
  if (typeof id !== 'string' || !/^\d{17}[\dXx]$/.test(id)) return false
  if (!PROVINCE_PREFIXES.has(id.slice(0, 2))) return false
  const year = Number(id.slice(6, 10))
  const month = Number(id.slice(10, 12))
  const day = Number(id.slice(12, 14))
  if (year < 1800 || year > 2099) return false
  if (month < 1 || month > 12) return false
  if (day < 1 || day > 31) return false
  return true
}

/**
 * Validate a retired 15-digit ID card number (province prefix plus a 19YY
 * birth date; the format carries no check character).
 * @param {string} id - candidate with no separators.
 * @returns {boolean} true when the value is a structurally valid legacy ID.
 */
export function isValidId15(id) {
  if (typeof id !== 'string' || !/^\d{15}$/.test(id)) return false
  if (!PROVINCE_PREFIXES.has(id.slice(0, 2))) return false
  const year = 1900 + Number(id.slice(6, 8))
  const month = Number(id.slice(8, 10))
  const day = Number(id.slice(10, 12))
  return isRealDate(year, month, day)
}

/**
 * Whether a value is a current mainland mobile number.
 * @param {string} value - 11 ASCII digits.
 * @returns {boolean} true when the number has a valid `1[3-9]` prefix.
 */
export function isMobile(value) {
  return typeof value === 'string' && MOBILE_RE.test(value)
}

/**
 * Luhn (MOD 10) checksum over ASCII digits.
 * @param {string} digits - digit string.
 * @returns {boolean} true when the checksum matches.
 */
export function passesLuhn(digits) {
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = digits.charCodeAt(index) - 48
    if (digit < 0 || digit > 9) return false
    if (double) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
    double = !double
  }
  return sum % 10 === 0
}

/**
 * Fold full-width ASCII (and the ideographic space) to ASCII.
 * Every replacement is one character for one character, so offsets in the
 * folded string address the same characters in the caller's original string.
 * @param {string} text - original text.
 * @returns {string} folded text with identical length.
 */
function foldFullWidth(text) {
  return text.replace(WIDE_FORMS_RE, (char) => String.fromCharCode(char.charCodeAt(0) - 0xFEE0))
}

/**
 * Classify one contiguous candidate token.
 * @param {string} candidate - raw token, still containing the original value.
 * @param {typeof DEFAULT_OPTIONS} options - effective options.
 * @returns {'id' | 'phone' | 'bank' | null} matched kind, or null to keep it.
 */
function classify(candidate, options) {
  // A leading `+` belongs to an international-format mobile number only.
  const token = candidate.startsWith('+') ? candidate.slice(1) : candidate
  // A trailing X only ever belongs to an 18-character ID number.
  if (/[Xx]$/.test(token)) {
    if (!options.redactIdCard) return null
    if (isValidId18(token)) return 'id'
    if (!options.strictIdChecksum && looksLikeId18(token)) return 'id'
    return null
  }
  if (options.redactIdCard) {
    if (token.length === 18) {
      if (isValidId18(token)) return 'id'
      if (!options.strictIdChecksum && looksLikeId18(token)) return 'id'
    }
    if (options.allowLegacyId15 && token.length === 15 && isValidId15(token)) return 'id'
  }
  if (options.redactPhone) {
    if (token.length === 11) return isMobile(token) ? 'phone' : null
    if (options.allowCountryCode && token.length === 13
      && token.startsWith('86') && isMobile(token.slice(2))) return 'phone'
    if (options.allowCountryCode && token.length === 15
      && token.startsWith('0086') && isMobile(token.slice(4))) return 'phone'
  }
  if (options.redactBankCard
    && token.length >= options.minBankCardLength
    && token.length <= options.maxBankCardLength
    && (!options.requireLuhn || passesLuhn(token))) {
    return 'bank'
  }
  return null
}

/**
 * Classify one grouped token by compacting it and reusing {@link classify}.
 * Every group must hold at least three digits, which keeps dates such as
 * `2026 11 05` (a two-digit month) out of the candidate set.
 * @param {string} token - grouped token including its separators.
 * @param {typeof DEFAULT_OPTIONS} options - effective options.
 * @returns {'id' | 'phone' | 'bank' | null} matched kind, or null to keep it.
 */
function classifyGrouped(token, options) {
  const groups = token.split(GROUP_SEPARATOR_RE)
  if (groups.length < 2) return null
  if (groups.some((group) => group.length < 3)) return null
  const digits = token.replace(GROUP_SEPARATOR_RE, '')
  if (digits.length < 11 || digits.length > 19) return null
  return classify(digits, options)
}

/**
 * Collect non-overlapping redaction spans over the folded text.
 * Contiguous candidates win first; grouped candidates are added only when they
 * do not overlap an existing span.
 * @param {string} folded - width-folded text.
 * @param {typeof DEFAULT_OPTIONS} options - effective options.
 * @returns {{ start: number, end: number, kind: string }[]} spans sorted by start.
 */
function collectSpans(folded, options) {
  const spans = []
  folded.replace(new RegExp(CANDIDATE_SOURCE, 'g'), (candidate, _group, offset) => {
    const kind = classify(candidate, options)
    if (kind !== null) spans.push({ start: offset, end: offset + candidate.length, kind })
    return candidate
  })
  folded.replace(new RegExp(GROUPED_SOURCE, 'g'), (token, _group, offset) => {
    const start = offset
    const end = offset + token.length
    const overlaps = spans.some((span) => start < span.end && end > span.start)
    if (overlaps) return token
    const kind = classifyGrouped(token, options)
    if (kind !== null) spans.push({ start, end, kind })
    return token
  })
  return spans.sort((left, right) => left.start - right.start)
}

/**
 * Replace every recognized PII value in one text with its placeholder.
 * @param {string} text - text to scan.
 * @param {Partial<typeof DEFAULT_OPTIONS>} [options] - overrides of the defaults.
 * @returns {{ text: string, counts: { id: number, phone: number, bank: number }, total: number }} rewritten text and per-kind counts.
 */
export function redactText(text, options) {
  const effective = options === undefined ? DEFAULT_OPTIONS : { ...DEFAULT_OPTIONS, ...options }
  const counts = { id: 0, phone: 0, bank: 0 }
  if (typeof text !== 'string' || text.length === 0) return { text, counts, total: 0 }
  const folded = foldFullWidth(text)
  const spans = collectSpans(folded, effective)
  if (spans.length === 0) return { text, counts, total: 0 }
  let rewritten = ''
  let cursor = 0
  for (const span of spans) {
    rewritten += text.slice(cursor, span.start)
    rewritten += PLACEHOLDERS[span.kind]
    cursor = span.end
    counts[span.kind] += 1
  }
  rewritten += text.slice(cursor)
  return { text: rewritten, counts, total: counts.id + counts.phone + counts.bank }
}

/**
 * Redact every text block of one message, preserving identity, source, and
 * every non-text block (image/file attachments are left alone).
 * @param {{ content: readonly { type: string, text?: string }[] }} message - message-shaped value.
 * @param {Partial<typeof DEFAULT_OPTIONS>} [options] - overrides of the defaults.
 * @returns {{ message: typeof message, counts: { id: number, phone: number, bank: number }, total: number }} possibly rewritten message and per-kind counts.
 */
export function redactMessage(message, options) {
  const counts = { id: 0, phone: 0, bank: 0 }
  const blocks = Array.isArray(message?.content) ? message.content : []
  let changed = false
  const content = blocks.map((block) => {
    if (block?.type !== 'text' || typeof block.text !== 'string') return block
    const result = redactText(block.text, options)
    if (result.total === 0) return block
    changed = true
    counts.id += result.counts.id
    counts.phone += result.counts.phone
    counts.bank += result.counts.bank
    return { ...block, text: result.text }
  })
  const total = counts.id + counts.phone + counts.bank
  if (!changed) return { message, counts, total: 0 }
  return { message: { ...message, content }, counts, total }
}
