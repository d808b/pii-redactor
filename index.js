/**
 * DSH Host plugin: local PII redaction for user input.
 *
 * Hook choice: `agent/pre-step` (waterfall). Its decision is what the agent loop
 * commits as the step's `user/message` events
 * (`@deepseek-ai/dsh-agent-loop/lib/index.js` step(), the `decision.messages`
 * append loop) and what every later request is assembled from
 * (`buildRequest()` -> `session.deriveMessages()`). Replacing the messages there
 * therefore makes the redacted text -- not the original -- the durable,
 * model-visible surface from the first step on.
 *
 * Redaction is NOT deletion: the original value still lands in this machine's
 * session log first, as part of the `agent/inbox/spliced` pending-input event.
 * Only the model-facing `user/message` surface is rewritten.
 *
 * `llm/stream` cannot do this job: for loop-built requests the GenerateOptions
 * handed to that waterfall is deep-frozen and documented as read-only
 * ("listeners read it, never rewrite it").
 *
 * This runs on the plugin's root context, which receives every agent's
 * `agent/pre-step` (scope-tagged listeners only see their own agent), so
 * subagents are covered too.
 *
 * @module @local/dsh-pii-redactor
 */

import { normalizeOptions, redactMessage } from './lib/patterns.js'

/** Loader entry name. */
export const name = 'pii-redactor'

/** Stable ASCII prefix so the warning is greppable in the host log. */
const LOG_PREFIX = '[pii-redactor]'

/** ANSI SGR yellow / reset. */
const YELLOW = '\u001b[33m'
const RESET = '\u001b[0m'

/**
 * Whether the log sink can render ANSI colors. Colors are only injected when
 * stderr is a terminal (or the operator forces them), so redirected logs keep
 * plain, searchable text.
 * @returns {boolean} true when colored output is appropriate.
 */
function colorEnabled() {
  try {
    if (process.env.NO_COLOR !== undefined || process.env.FORCE_COLOR === '0') return false
    return process.stderr?.isTTY === true || process.env.FORCE_COLOR !== undefined
  } catch {
    return false
  }
}

/**
 * Print one yellow warning line without leaking any original value.
 * Tries the Cordis logger, then the console, and never throws into the agent
 * loop: a logging failure must not discard an already-redacted decision.
 * @param {object} ctx - plugin context.
 * @param {string} line - already-safe message (counts only, never values).
 */
function warnYellow(ctx, line) {
  const text = colorEnabled() ? `${YELLOW}${line}${RESET}` : line
  try {
    ctx.logger.warn(text)
    return
  } catch {
    /* logger service missing: fall through to the console sink */
  }
  try {
    console.warn(text)
  } catch {
    /* no sink at all: redaction still stands, the warning is best effort */
  }
}

/**
 * Whether one claimed message is in scope for redaction.
 * @param {{ source?: { kind?: string } }} message - claimed user message.
 * @param {ReturnType<typeof normalizeOptions>} options - effective options.
 * @returns {boolean} true when the message's text should be scanned.
 */
function shouldRedact(message, options) {
  if (options.redactInjectedContext) return true
  return message?.source?.kind === 'user'
}

/**
 * Compose the one-line warning shown to the operator.
 * @param {{ id: number, phone: number, bank: number }} counts - per-kind counts.
 * @param {number} total - total redacted values.
 * @param {{ turn?: number, step?: number }} where - step position, when known.
 * @returns {string} the warning line.
 */
function warningLine(counts, total, where) {
  const parts = []
  if (counts.id > 0) parts.push(`身份证 ${counts.id}`)
  if (counts.phone > 0) parts.push(`手机号 ${counts.phone}`)
  if (counts.bank > 0) parts.push(`银行卡 ${counts.bank}`)
  const position = Number.isFinite(where.turn) && Number.isFinite(where.step)
    ? ` turn=${where.turn} step=${where.step}`
    : ''
  return `${LOG_PREFIX} 已拦截并替换 ${total} 条敏感信息（${parts.join(' / ')}），本步已脱敏放行。${position}`
}

/**
 * Apply the engine to one `enter` decision.
 * @param {{ messages: readonly object[] }} decision - pre-step decision.
 * @param {ReturnType<typeof normalizeOptions>} options - effective options.
 * @returns {{ messages: object[], counts: { id: number, phone: number, bank: number }, total: number } | undefined} rewritten messages and counts, or undefined when nothing matched.
 */
function redactDecision(decision, options) {
  const totals = { id: 0, phone: 0, bank: 0 }
  let changed = false
  const messages = decision.messages.map((message) => {
    if (!shouldRedact(message, options)) return message
    const result = redactMessage(message, options)
    if (result.total === 0) return message
    changed = true
    totals.id += result.counts.id
    totals.phone += result.counts.phone
    totals.bank += result.counts.bank
    return result.message
  })
  if (!changed) return undefined
  return { messages, counts: totals, total: totals.id + totals.phone + totals.bank }
}

/**
 * Shorten an unexpected error for the warning line, so a long value-bearing
 * message cannot be echoed into the log verbatim.
 * @param {unknown} error - thrown value.
 * @returns {string} bounded, single-line description.
 */
function describeError(error) {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
  return text.replace(/\s+/g, ' ').slice(0, 160)
}

/**
 * Plugin entry.
 * @param {object} ctx - Cordis plugin context.
 * @param {object} [config] - the Loader row's `config` block.
 */
export function apply(ctx, config) {
  const options = normalizeOptions(config)
  if (!options.enabled) return

  ctx.on('agent/pre-step', async (payload, next) => {
    const decision = await next()
    // Only an `enter` decision carries messages; `reject` is passed through.
    if (decision === null || typeof decision !== 'object' || decision.kind !== 'enter') {
      return decision
    }
    if (!Array.isArray(decision.messages)) return decision

    let redacted
    try {
      redacted = redactDecision(decision, options)
    } catch (error) {
      // Never silent: the operator must see that this step went out unredacted.
      const action = options.failClosed ? '已按 failClosed 阻断本步' : '消息按原文放行'
      warnYellow(ctx, `${LOG_PREFIX} 脱敏失败，${action}：${describeError(error)}`)
      return options.failClosed ? { kind: 'reject' } : decision
    }
    if (redacted === undefined) return decision

    // Emitted outside the try: a logging failure must not discard the rewrite.
    warnYellow(ctx, warningLine(redacted.counts, redacted.total, payload ?? {}))
    // Spread the decision so fields such as `startsRequestSeries` survive.
    return { ...decision, messages: redacted.messages }
  })
}
