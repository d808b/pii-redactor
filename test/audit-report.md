# PII 脱敏插件对抗性审查报告

- 审查对象：`pii-redactor/`（`lib/patterns.js` 引擎 + `index.js` Host 插件接线 + `cordis.patch.yml`）
- 审查方式：只读审查 + 新建 `test/audit.test.mjs`（48 个测试：45 通过 + 3 个 `todo` 记录已知漏检）
- 基线：审查前 `node --test` = **25/25 全绿**；审查后 `node --test` = **73 个测试，70 通过、0 失败、3 todo，退出码 0**
- 本文档遵守脱敏纪律：**不出现任何真实证件号/卡号/手机号**，只写模式、长度与计数；文中 `#` 表示任意数字，`…` 表示省略。

---

## 结论

**不可按当前文档直接交付。** 引擎对「裸数字」格式的正确性很高（合法样本 0 漏检、校验位实现与独立实现一致），接线本身也满足 `agent/pre-step` 契约；但存在 **2 个真实可绕过的漏检（全角数字、分组/分隔符格式）**、**1 个会给出虚假安全感的安全选项（`redactInjectedContext` 对 `runtime-context` 完全无效）**，以及 **1 处与事实不符的"持久化安全"声明**。上述 4 项修复前建议不对外宣称"PII 不会进入模型"。其余为误报率与稳健性改进。

| 维度 | 判定 |
|---|---|
| 合法样本漏检（裸格式） | 0（500 ID / 500 手机号 / 300 卡号 全命中） |
| 可格式化绕过 | **有**：全角数字、空格/横线分组、无分隔粘连 |
| 误报率（随机 16–19 位） | 10.2%～10.5%，与 Luhn 理论 10% 一致（见「误报率」） |
| `agent/pre-step` 契约 | **成立**（行号见「契约核对」） |
| 日志泄值 | 成功/失败路径均只含计数；残余风险见建议 S-3 |

---

## 必须修复（按严重度排序）

### MF-1（高，漏检）全角数字完全不被识别 —— 静默放行 PII

- **复现输入**：全角 11 位数字（形如 `１３８…`，字符码 U+FF11…），放在中文文本中。
- **实际**：`redactText('电话１３８…')` 原样返回，`counts` 全 0。
- **期望**：命中为 `[PHONE]`（同理全角 18 位证件号应为 `[ID]`）。
- **根因**：`CANDIDATE_RE` 的 `\d` 在 JS 中只匹配 ASCII `0-9`（`lib/patterns.js:50`），`charCodeAt(i)-48` 的校验计算也假定 ASCII（`lib/patterns.js:146`）。中文输入法（全角模式）或从网页/表单复制时极易产生全角数字，属于真实世界高频输入。
- **证据**：`test/audit.test.mjs` → `E1: known FN - full-width digits are not redacted`（todo）。
- **修复方向**：匹配前对文本做 NFKC 归一化（`text.normalize('NFKC')`）后再扫描；若需保留原文排版，可对归一化副本扫描并按映射回填，或至少在接受候选 token 前将其 NFKC 化再做 classify。

### MF-2（高，漏检）分组/分隔符格式不被识别 —— 银行卡与手机号的高频书写方式

- **复现输入**：
  - 手机号 `138 #### ####`、`138-####-####`（3-4-4 分组）；
  - 卡号 16 位按 `#### #### #### ####` 分组（形如 `6222 #### #### ####`）。
- **实际**：全部原样返回；16 位分组卡号 `counts.bank === 0`。
- **期望**：`[PHONE]` / `[BANK]`（银行短信、对账单、名片上的标准写法就是分组显示）。
- **根因**：候选正则要求连续 11–19 位数字（`lib/patterns.js:50`），空格/横线直接截断 token，任何一段都短于最小长度。
- **证据**：`test/audit.test.mjs` → `E2: known FN - mobiles/cards written in groups are not redacted`（todo）。
- **修复方向**：增加"分隔符容错"预扫描：先匹配 `(?:\d[ -]?){11,19}` 形态，去掉分隔符后走现有 `classify`；或对常见分组形态（4-4-4-4、3-4-4）单独建模式。注意避免把 `2026 11 05` 之类日期误判为卡号（仍由 Luhn 兜底）。

### MF-3（中，契约不符 / 虚假安全感）`redactInjectedContext: true` 对 `runtime-context` 消息完全无效

- **复现（代码级，需真实 agent 循环）**：开启 `redactInjectedContext: true`，向本步注入带 PII 的 `runtime-context` 消息。
- **实际**：插件确实改写了该消息（`test/audit.test.mjs` → `H6` 通过），但 agent 循环**丢弃**改写结果：`decision.messages` 中 `source.kind === "runtime-context"` 的消息不落库，循环用**重新投影**的 `context` 代替（`dsh-agent-loop/lib/index.js:859-866`，其中新 `context` 来自 `:843-847`）。因此内存召回/上下文注入路径上的 PII 仍以原文进入模型。
- **期望**：该选项的语义（`lib/patterns.js:72-73` 注释、`index.js` 设计意图）应真实覆盖注入上下文；至少文档必须明确"runtime-context 不在覆盖范围"。
- **证据**：`@deepseek-ai/dsh-agent-loop/lib/index.js:859-866`（runtime-context 被跳过、只追加新投影的 `context`）；对照 `:691-696`（pre-step 默认把投影后的 context 放进 messages）。
- **修复方向**：二选一 —— ① 在更高层（system-prompt 组装/`system/message` 落库处）脱敏，使投影结果本身被改写；② 若宿主不提供该层，则把选项描述与 README 改为"仅覆盖非 runtime-context 的注入消息"，避免虚假安全感。

### MF-4（中，文档与事实不符）"durable surface" 声明错误：原文仍持久化在会话日志中

- **复现（代码级）**：用户提交含 PII 的 prompt，观察会话事件日志。
- **实际**：原始文本在 pre-step **之前**就已落入会话事件日志：`send()` → `inbox.splice` → `mutate` → `session.append("agent/inbox/spliced", { inserted: [原始 message] })`（`dsh-agent-loop/lib/index.js:564-568`、`:159-161`、`:190-198`），`Session.append` 会 JSON 快照并 commit 到持久化日志（`dsh-session/lib/index.js:1524` 起）。脱敏只改了 `user/message` 这条 surface 事件。
- **期望**：`index.js:6-8` 现在写的是"redacted text … becomes the durable, model-visible surface"，容易被读成"原文不落盘"。准确表述应为：**模型可见面已脱敏；原文仍以 inbox 事件形式留在会话日志中**（脱敏 ≠ 抹除）。
- **证据**：`@deepseek-ai/dsh-agent-loop/lib/index.js:194-198`（`inserted` 含原始消息）、`:564-568`；`dsh-session/lib/index.js:1524` 起（append 持久化）。
- **修复方向**：修正头注释与 README 措辞，并给运维提示：会话日志属敏感载体，需要额外的 at-rest 清理/加密策略。

---

## 建议改进（不阻塞交付）

- **S-1（误报）银行卡 10% 随机命中**：`requireLuhn` 让任意 16–19 位数字有 1/10 被替换成 `[BANK]`（实测 10.19%～10.53%）。订单号、设备编号、19 位流水号都会被误伤。建议在 Luhn 之外再加 BIN 前缀白名单（如 `62/4/5/3/35/37/60xx`），可把随机误报压到 <1%，同时不损失真实卡号覆盖。
- **S-2（误报）手机号 7% 随机命中**：`1[3-9]` 只约束前两位，随机 11 位数字有 7% 概率被替换（实测 7.00%）。这是号段规则本身的极限，可接受；若业务有 11 位非手机编号，建议加"上下文关键词"（电话/手机/联系）加权，或提供按会话关闭开关。
- **S-3（稳健性）日志失败会把"已成功脱敏"降级为"原文放行"**：`index.js:120` 的 `warnYellow` 位于 `try` 内，`catch`（`:123-128`）返回的是**原始** `decision`。若 `console.warn` 被关闭/替换后抛错（logger 异常已内部兜底，但 console 兜底没有），一个已经算好的脱敏结果会被丢弃并以原文放行。建议把告警移到 `try` 之外，或对 `warnYellow` 整体再包一层；同时把 `error.message` 截断/只记 `error.name`，让"日志绝不含原值"成为硬不变量（现只对普通 Error 成立，见 `H8`）。
- **S-4（文档）`lib/patterns.js:44-49` 的注释举了错误例子**：注释称 `order_id_6222…` 不会被当成卡号，但实际上 `_` **属于**边界（边界类只有 `[0-9A-Za-z]`），该样例之所以未被替换是因为它 Luhn 不通过；换成 Luhn 合法的值就会被替换（`test/audit.test.mjs` → `C2b` 已固化该行为）。建议改注释，或把 `_` 并入边界类。
- **S-5（一致性）`isFutureDate` 的时区**：注释写 Asia/Shanghai（`lib/patterns.js:115`），实现用宿主本地时区（`:118-119`）。跨时区机器上"未来出生日期"的判定会差一天（仅在边界日期可见）。建议显式用 `Asia/Shanghai` 计算，或改注释。
- **S-6（策略）失败即放行（fail-open）**：引擎异常时按原文发送（`index.js:123-128`）。当前实现"不静默"（会告警），符合任务书要求；但对高敏场景建议提供 `failClosed: true` 选项（异常时返回 `reject` 或整步阻断），让部署方按合规等级选择。
- **S-7（审计）告警只写一行 warn**：等保/审计场景建议同时发一个结构化事件（计数 + turn/step + 策略名），便于集中采集；当前行内文本已足够人读。
- **S-8（覆盖）默认 `redactInjectedContext: false`**：如果产品目标是"PII 不进入模型"，注入上下文默认不脱敏是个缺口（见 MF-3 的宿主限制）。建议在 README 里显式写明默认边界。

---

## 误报率 / 漏检率（实测）

统计口径：固定种子 `mulberry32`，数字逐位均匀采样，每项 3000 个样本（报告另附 20000 样本复核）；断言为区间，故结果可复现。测试内 `t.diagnostic` 会打印实测值。

| 测量项 | 实测 | 理论 | 判定 |
|---|---|---|---|
| 随机 16–19 位 → `[BANK]` | **10.53%**（316/3000）；复核 10.19%（2038/20000） | 1/10 = 10% | 与 Luhn 理论一致（说明银行判定**只**靠 Luhn） |
| 随机 18 位 → `[ID]` | **0/3000**；复核 1/20000 = 0.005% | ≈3.4e-5（省前 35% × 日期 ~3.6% × 年份 3% × 1/11） | 与理论同量级 |
| 随机 11 位 → `[PHONE]` | **6.10%**（183/3000）；复核 7.00%（1400/20000） | 1/10 × 7/10 = 7% | 与号段理论一致 |
| 「省前 + 合法生日 + 随机末位」18 位 → `[ID]` | **8.20%**（246/3000） | 1/11 = 9.09% | 与校验位理论一致 → **未校验顺序码/性别/地址真实性** |

**漏检（false negative）**：
- 裸格式：500 个合成合法身份证、500 个合成合法手机号、300 个 Luhn 合法卡号（16/17/19 位）+ 18 位非省前卡号 → **0 漏检**。
- 已知漏检（均为可复现的静默放行）：
  1. 全角数字（`Ｅ1`）；
  2. 空格/横线分组（`Ｅ2`，3 种形态）；
  3. 两个 PII 无分隔粘连（`E3`，如 18 位 + 11 位连写 → 整体超过 19 位，整段不匹配）。
- 另外：ASCII 字母/数字**紧邻**即不匹配（`abc<号码>def`），这是文档化设计（`lib/patterns.js:43-49`），但意味着"订单号=手机号"这类拼接写法会漏。

**幂等性**：混排文本二次运行 `total === 0` 且文本逐字符不变；`[ID]/[PHONE]/[BANK]` 不含数字，故不会被二次匹配（`F1`、`F2`、`C5`）。

---

## 契约核对结果（含行号）

被测前提："pre-step 返回的 `messages` 会成为持久 `user/message` 并进入后续请求的模型可见 surface"。

**结论：成立（对 `source.kind === 'user'` 的消息），但有两个必须写清的边界。**

1. **pre-step waterfall 的返回值就是本步的消息源**
   `@deepseek-ai/dsh-agent-loop/lib/index.js:685-697`：`dispatch.waterfall("agent/pre-step", { messages: claimed, ...position, signal, modelSelection }, fallback)`，fallback 返回 `{ kind:"enter", messages: claimed | [...claimed, context] }`。插件的 `(payload, next)` 签名与 Cordis 语义一致（`@deepseek-ai/cordis/lib/index.js:903-921`：监听器拿 `(payload, next)`，最外层返回值为最终结果；不调用 `next()` 即否决）。插件恰好调用 `next()` 一次（`H2` 断言 `calls === 1`），满足要求。

2. **`decision.messages` 被逐条落库为 `user/message`**
   `dsh-agent-loop/lib/index.js:742-745` 取回 `decision`；`:751-754` 用 `decision.messages.length` 判定空步；`step()` `:860-865`：`for (const message of decision.messages) if (source.kind === "runtime-context") {…} else this.session.append("user/message", message, { surfaceOp: "append" })`。→ 插件替换后的消息（含 `id`/`source` 保留）就是落库内容。

3. **请求体来自会话 surface，而不是旧的内存副本**
   `buildRequest` `:1018`，`:1078` `const boundaryMessages = session.deriveMessages()`，`:1085-1092` 请求里 `messages: boundaryMessages`；`dsh-session/lib/index.js:1681-1696` 的 `deriveMessages()` 只遍历 `surface.nodes`（`:1690-1693`）。→ 后续每一步请求读到的都是被替换后的 surface 消息，契约成立。

4. **`startsRequestSeries` 等其它字段保留**
   插件 `index.js:121-122` 用 `{ ...decision, messages }`；框架侧 `dsh-agent-loop/lib/index.js:849` 读取 `decision.startsRequestSeries`。`H2` 断言 `startsRequestSeries` 与自定义字段都存活。

5. **`reject` 直通**
   插件 `index.js:101-103` 对非 `enter` 原样返回（`H4` 用 `assert.equal(out, decision)` 断言同一引用）；框架侧 `:699-702` 与 `:746-749` 在 `reject` 时直接结束该轮。

6. **边界 A（必须写清）：`runtime-context` 消息的改写被丢弃**
   `:860-866` 对 `runtime-context` 不落库，只追加 `:847` 重新投影的 `context`。→ 任何对该类消息的脱敏都无效（MF-3）。

7. **边界 B（必须写清）：原文在 pre-step 之前已持久化**
   `:564-568` → `:159-161` → `:190-198`：`agent/inbox/spliced` 事件携带 `inserted: [原始消息]` 并 `session.append`。→ 模型面安全 ≠ 落盘安全（MF-4）。

8. **位置信息可用**：`:685-689` 的 `...position`（`turn`/`step`）确实在 payload 里，`H2` 断言日志含 `turn=4 step=2`；`payload` 缺失时 `index.js:120` 的 `payload ?? {}` 不会崩（`warningLine` 用 `Number.isFinite` 守卫）。

---

## 未验证项

1. **未做真实安装验证**：按纪律未跑 `plugin_manager install_bundle`、未合并 `cordis.patch.yml`、未改 profile。因此以下均**未实测**：插件在真实 Cordis profile 中的加载、`ctx.logger` 服务的实际存在性、`cordis.patch.yml` 的 `config` 是否能被 `normalizeOptions` 正确解析、`icon.svg`/`locale/` 是否能被 UI 加载。
2. **root context 是否覆盖子代理**：`index.js:11-14` 声称根上下文能收到所有 agent 的 `agent/pre-step`（含子代理）。这依赖宿主的作用域过滤（`cordis/lib/index.js` 的 `Context.filter` 机制），**未经运行验证**。
3. **MF-3 的 runtime-context 结论来自代码阅读**（行号已给），未在真实 agent 循环里端到端复现（需要落地 model provider）。
4. **memory-recall 消息的真实 `source.kind`**：未安装记忆插件，"内存召回走 runtime-context"是基于宿主投影逻辑的推断；结论仅对 `runtime-context` 成立。
5. **UI/转录呈现**：本地聊天界面显示的是脱敏后的 `user/message` 还是原始输入，未验证（影响用户体验，不影响模型面）。
6. **真实业务样本的误报影响**：10% 银行卡误报对现场真实订单号/流水号字段的影响，需要用脱敏后的真实样本再统计一次（本次只用均匀随机数）。
7. **跨时区**：`isFutureDate` 在非 Asia/Shanghai 宿主上的边界行为未测（本机为 CST）。
8. **`NO_COLOR`/`FORCE_COLOR`** 在真实宿主日志（TTY / 重定向）中的表现未测；只做了 `console.warn` 兜底路径的单测（`H9`）。
9. **fail-open 的实际风险面**：未统计真实运行中引擎异常的频率（当前只证明异常时"告警 + 原文放行"）。

---

## 附：本次新增测试清单（`test/audit.test.mjs`）

| 组 | 覆盖 |
|---|---|
| A1–A7 | 独立实现交叉验证：MOD 11-2 权重按 `2^(18-i) mod 11` 独立推导；Luhn 独立实现；全 11 个校验字符的接受/拒绝；15 位旧证；含 `X` 样本 |
| B1–B9 | 合法样本零漏检：500 ID / 500 手机号 / 300 卡号；句首句尾；中文/全角标点/换行/emoji；相邻分隔；`86`/`0086`；15 位开关 |
| C1–C5 | 误伤边界：时间戳/epoch/IP:端口/版本号；20+ 位长串与字母包夹；UUID/hex/base64/路径；长度窗口与 `requireLuhn`；占位符惰性 |
| C2b | 定界符语义：`_` 属于边界（与源码注释不符，已固化证据） |
| D1–D4 | 误报率（固定种子 3000 样本，含理论对照） |
| E1–E3 | 已知漏检（`todo`，断言"期望行为"，修复后自动转绿） |
| F1–F2 | 幂等性（含占位符相邻场景） |
| G1–G3 | `redactMessage` 身份/来源/非文本块/畸形输入 |
| H1–H10 | 接线：单监听器、字段保留、计数日志、reject/空/畸形直通、深冻结输入、注入上下文开关、失败告警不泄值、logger 兜底、上游异常不吞 |
| I1–I4 | `normalizeOptions` 失败安全：类型不匹配/未知键/`"false"` 字符串/原型污染均**不能**关闭脱敏 |

---

## 复核（修复后，2026-11-12，lead）

本节为修复后的复核记录，**不改写上面的原始结论**，只追加状态。

### 必须修复项处置

| 编号 | 处置 | 证据 |
|---|---|---|
| MF-1 全角数字漏检 | ✅ 已修：`foldFullWidth()` 做 1:1 宽度折叠（`\u3000`、`\uFF01-\uFF5E`），扫描用折叠副本、替换回填原文字符区间 | `lib/patterns.js` `foldFullWidth` + `redactText`；用例 `patterns.test.mjs` “folds full-width IME input”、`audit.test.mjs` E1（已从 todo 转正） |
| MF-2 分组/分隔符漏检 | ✅ 已修：新增 `GROUPED_SOURCE` + `classifyGrouped()`，空格/不换行空格/连字符分组先拼接再走同一 `classify`；每组 ≥3 位以排除 `2026 11 05` | `lib/patterns.js` `GROUPED_SOURCE` / `classifyGrouped` / `collectSpans`；`audit.test.mjs` E2（转正）、`patterns.test.mjs` 分组用例 |
| MF-3 `redactInjectedContext` 对 `runtime-context` 无效 | ✅ 已按“二选一”的第二种处置：**明确写清边界**。选项注释、README 第 1 节第 6 行、配置表均声明宿主内置 `runtime-context` 快照的改写会被循环丢弃；该选项只覆盖以普通 `user/message` 入日志的注入消息 | `lib/patterns.js` `DEFAULT_OPTIONS.redactInjectedContext` 注释；`README.md` 第 1 节 |
| MF-4 “durable” 声明与事实不符 | ✅ 已修：`index.js` 头注释改为“redacted text … the durable, model-visible surface”，并新增一段明说 **Redaction is NOT deletion**、原文仍以 `agent/inbox/spliced` 落盘 | `index.js` 头注释；`README.md` 第 1 节第 2 行 |

### 建议项处置

| 编号 | 处置 |
|---|---|
| S-3 告警失败会丢弃已算好的脱敏结果 | ✅ 已修：告警移到 `try` 之外，`warnYellow` 三层兜底（logger → console → 静默），日志失败不再影响改写结果 |
| S-4 `order_id_6222…` 注释错误 | ✅ 已修：注释改为说明边界含 `_`，并注明该样例只是 Luhn 不通过 |
| S-5 `isFutureDate` 时区 | ✅ 已修：显式按 UTC+8 的日历日比较，与注释一致 |
| S-6 fail-open / fail-closed | ✅ 已加 `failClosed` 选项（默认 `false`），异常时按配置 `reject` 或原文放行 |
| S-1 BIN 白名单压误报 | ⏸ 未内置：会把未知 BIN 的真实卡号一起漏掉，与“防泄漏优先”冲突；README 已写明可选做法 |
| S-2 手机号 7% 随机命中 | ⏸ 不修：号段规则本身的极限，属可接受误报 |
| S-7 结构化审计事件 | ⏸ 未做：当前一行 warn 已满足人读与 grep，集中采集需要额外的日志管道契约 |

### 复核后的测试状态

```
node --test
ℹ tests 77　ℹ pass 76　ℹ fail 0　ℹ todo 1
```

- `audit.test.mjs` E1/E2 已由 `todo` 转为正常用例并通过；
- E3（两段 PII 无分隔粘连）保留 `todo`，作为**结构化限制**记录，不计划修复；
- `patterns.test.mjs` 增补 3 条（全角、分组、分隔日期不误判），`plugin.test.mjs` 增补 1 条（`failClosed` 拒绝）。

### 仍未验证（与上文一致）

1. 真实安装（`plugin_manager install_bundle`）与 profile 加载；
2. 根上下文是否覆盖子代理（依赖宿主作用域过滤，需实跑）；
3. 插件管理器内标题/描述/图标渲染；
4. 记忆插件召回消息的真实 `source.kind`。

### 补充：安装后实测（2026-11-12，lead）

上面「未验证」第 1、2 项已补测：

- **安装**：`plugin_manager install_bundle` → `application: applied`、`version 0.1.1`、`warnings: []`；
  profile 的 `cordis.patch.yml` **未改动**（备份 diff 为空），仅 `package.json` 增加
  `@local/dsh-pii-redactor` 的 `link:` 依赖与 `dsh.profile.bundles` 条目；四个既有插件目录仍在，lockfile 顶层条目无差异。
- **真实链路（含子代理）**：以子代理会话实测，其 prompt 含合成手机号 / Luhn 合法卡号 / 合法身份证。
  - 子代理回显：`手机号 [PHONE]，卡号 [BANK]，身份证 [ID]`（模型侧只见占位符）；
  - 该子会话日志（29 事件）中 `user/message` 共 6 条，**1 条含占位符、0 条含原文**；
    `agent/inbox/spliced` **1 条含原文**——与 MF-4 的边界描述一致（surface 脱敏、落盘留原文）；
  - 由此确认根上下文监听确实覆盖子代理。

仍未验证：黄色警告行在真实终端的**颜色**（单测覆盖了 warn 路径与“日志不含原值”，颜色取决于宿主 TTY）、
插件管理器里的标题/描述/图标渲染。
