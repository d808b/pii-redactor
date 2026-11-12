import assert from 'node:assert/strict'
import test from 'node:test'

import { apply } from '../index.js'

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK_CHARS = '10X98765432'

function withCheckDigit(base17) {
  let sum = 0
  for (let index = 0; index < 17; index += 1) sum += Number(base17[index]) * ID_WEIGHTS[index]
  return base17 + ID_CHECK_CHARS[sum % 11]
}

const VALID_ID = withCheckDigit('11010119900307447')

/** Minimal Cordis-like context that records the registered listener. */
function makeContext() {
  const listeners = new Map()
  const logs = []
  const ctx = {
    on(name, listener) {
      listeners.set(name, listener)
      return () => listeners.delete(name)
    },
    logger: { warn: (line) => logs.push(line) },
  }
  return { ctx, listeners, logs }
}

function userMessage(id, text) {
  return { id, role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text }] }
}

test('registers exactly one agent/pre-step listener', () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, {})
  assert.deepEqual([...listeners.keys()], ['agent/pre-step'])
})

test('does not register anything when disabled', () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, { enabled: false })
  assert.equal(listeners.size, 0)
})

test('rewrites user text, keeps identity, and logs one yellow line', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const handler = listeners.get('agent/pre-step')
  const decision = {
    kind: 'enter',
    messages: [userMessage('m-1', `我的身份证 ${VALID_ID}，电话 13812345678`)],
    startsRequestSeries: true,
  }
  const out = await handler({ turn: 1, step: 1 }, async () => decision)
  assert.equal(out.kind, 'enter')
  assert.equal(out.startsRequestSeries, true, 'decision fields must survive')
  assert.equal(out.messages[0].id, 'm-1')
  assert.equal(out.messages[0].source.kind, 'user')
  assert.equal(out.messages[0].content[0].text, '我的身份证 [ID]，电话 [PHONE]')
  assert.equal(logs.length, 1)
  assert.match(logs[0], /已拦截并替换 2 条敏感信息/)
  assert.match(logs[0], /身份证 1 \/ 手机号 1/)
  assert.match(logs[0], /turn=1 step=1/)
  assert.equal(logs[0].includes(VALID_ID), false, 'log must not leak the original value')
})

test('passes a reject decision through untouched', async () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, {})
  const out = await listeners.get('agent/pre-step')({}, async () => ({ kind: 'reject' }))
  assert.deepEqual(out, { kind: 'reject' })
})

test('leaves injected runtime context alone by default', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const injected = {
    id: 'ctx-1',
    role: 'user',
    source: { kind: 'runtime-context' },
    content: [{ type: 'text', text: `recall: ${VALID_ID}` }],
  }
  const decision = { kind: 'enter', messages: [injected] }
  const out = await listeners.get('agent/pre-step')({}, async () => decision)
  assert.equal(out, decision, 'unchanged decision should be returned as-is')
  assert.equal(logs.length, 0)
})

test('redacts injected context when asked to', async () => {
  const { ctx, listeners } = makeContext()
  apply(ctx, { redactInjectedContext: true })
  const injected = {
    id: 'ctx-1',
    role: 'user',
    source: { kind: 'runtime-context' },
    content: [{ type: 'text', text: `recall: ${VALID_ID}` }],
  }
  const out = await listeners.get('agent/pre-step')({}, async () => ({ kind: 'enter', messages: [injected] }))
  assert.equal(out.messages[0].content[0].text, 'recall: [ID]')
})

test('fails open with a warning when the engine throws', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, {})
  const hostile = {
    id: 'm-9',
    role: 'user',
    source: { kind: 'user' },
    get content() {
      throw new Error('boom')
    },
  }
  const decision = { kind: 'enter', messages: [hostile] }
  const out = await listeners.get('agent/pre-step')({}, async () => decision)
  assert.equal(out, decision)
  assert.match(logs[0], /脱敏失败，消息按原文放行/)
})

test('rejects the step under failClosed when the engine throws', async () => {
  const { ctx, listeners, logs } = makeContext()
  apply(ctx, { failClosed: true })
  const hostile = {
    id: 'm-10',
    role: 'user',
    source: { kind: 'user' },
    get content() {
      throw new Error('boom')
    },
  }
  const decision = { kind: 'enter', messages: [hostile] }
  const out = await listeners.get('agent/pre-step')({}, async () => decision)
  assert.deepEqual(out, { kind: 'reject' })
  assert.match(logs[0], /已按 failClosed 阻断本步/)
})
