# pii-redactor — DSH 本地 PII 脱敏插件

在用户消息进入模型请求之前，把**中国大陆身份证号 / 手机号 / 银行卡号**在本地替换为
`[ID]` / `[PHONE]` / `[BANK]`，并打印一行黄色警告（只含计数，不含原值）。

- 包名：`@local/dsh-pii-redactor`　Loader 行 id：`pii-redactor`
- 形态：Host-only bundle（无运行时依赖、无构建步骤）
- 挂载点：`agent/pre-step`（waterfall，模型请求组装之前）
- 当前版本：`0.2.1`（身份证默认**严格**：校验位必须匹配；兜底是可选开关，默认关）

---

## 1. 它拦在哪一层（能力边界，先看这段）

**生效链路**（已核对内核源码，行号为 `@deepseek-ai/dsh-agent-loop/lib/index.js`）：

1. `pre-step` 的 waterfall 监听器返回 `{ kind:'enter', messages }`；
2. agent loop 逐条把这批 messages `session.append("user/message", message, { surfaceOp:'append' })`
   （`step()`，第 860–866 行）；
3. 组装请求时用 `session.deriveMessages()` 从会话 surface 重建历史（`buildRequest()`，第 1078 行）。

所以**脱敏后的文本会作为持久的 `user/message` 进入会话，并成为模型可见 surface 的一部分**——
不是只改这一次请求，而是从第一步起、以及之后每一轮从日志重建的历史都只有占位符。

**为什么不用 `llm/stream`**：对 agent loop 构造的请求，该 waterfall 拿到的 `GenerateOptions`
是深冻结的，且契约明确写着 “listeners read it, never rewrite it”
（`@deepseek-ai/dsh-llm/lib/types/index.d.ts:40`）。在那里改写会直接抛错。

**它拦不住什么（如实列出）**：

| # | 情况 | 说明 |
|---|---|---|
| 1 | 输入框回显 / GUI 显示 | 原文仍显示在本地界面，模型收到的已是占位符 |
| 2 | 本机会话文件 | `agent/inbox/spliced` 事件里仍保留原文（本地落盘，**不随模型请求外发**） |
| 3 | 语义型 PII | 姓名、住址、单位名、客户联系人——正则无解，只能靠“入口不入” |
| 4 | 其它分隔符写法 | 只认空格 / 不换行空格 / 连字符；`6222/0212/3456/7890`、`6222.0212.3456.7890` 不匹配 |
| 5 | 非 agent-loop 的模型调用 | 手搓请求（不经 `agent/pre-step`）不覆盖；判据是调用方是否走 agent loop |
| 6 | 宿主内置 `runtime-context` 快照 | 循环会**丢弃**插件对该类消息的改写（`step()` 第 860–866 行），改用自己重新投影的 context；`redactInjectedContext` 只对以普通 `user/message` 入日志的注入消息（如记忆召回）有效 |
| 7 | 两段 PII 无分隔粘连 | `身份证+手机号` 连写会成为一个超长数字串，超出候选边界被跳过 |

**正面证据**：记忆插件 `dsh-prime-memory` 的 L0 捕获只监听 `user/message` 等 5 类事件
（`dist/hooks/capture.js` 的 `RELEVANT_TYPES`），**不读 `agent/inbox/spliced`**——因此它捕获到的
也是脱敏后的文本，不会把原文带进蒸馏。

---

## 2. 文件结构

```
pii-redactor/
├── package.json          # bundle 清单：exports / files / dsh.bundle.patch
├── cordis.patch.yml      # 插入 Loader 行 + 默认 config（安装时并入 profile）
├── index.js              # Host 插件：apply() + agent/pre-step 监听 + 黄色告警
├── lib/
│   └── patterns.js       # 纯函数引擎：正则、校验位、占位符替换（可独立单测）
├── locale/
│   ├── en.json           # meta.title / meta.description（插件管理器展示用）
│   └── zh.json
├── icon.svg              # 自有图标（盾牌 + 三条打码线）
├── test/
│   ├── patterns.test.mjs # 引擎单测（21 个）
│   ├── plugin.test.mjs   # 插件接线单测（8 个，用 stub ctx 跑 pre-step）
│   ├── audit.test.mjs    # 独立对抗性审查用例（48 个，1 条 todo=已知结构限制）
│   └── audit-report.md   # 审查报告（结论/缺陷/误报率/契约行号）
└── README.md
```

---

## 3. 检测规则（“高精度”是怎么来的）

不靠“长度像就替换”，每类都过真校验：

| 类型 | 匹配 | 硬校验 | 占位符 |
|---|---|---|---|
| 身份证 18 位（严格） | 11–19 位数字候选中的 18 位 | 前 2 位省份码白名单 + 出生日期真实存在且不在未来 + **ISO 7064 MOD 11-2 校验位**（末位 `X/x` 允许） | `[ID]` |
| 身份证 18 位（兜底，**可选**，默认关） | 同上 | 省份码白名单 + `YYYYMMDD` 字段范围合法即可，**不看校验位/闰年/未来日期** | `[ID]` |
| 身份证 15 位（默认关） | 15 位 | 省份码 + `19YYMMDD` 真实日期 | `[ID]` |
| 手机号 | `1[3-9]` + 9 位；可选 `86` / `0086` / `+86` 前缀 | 号段前缀 | `[PHONE]` |
| 银行卡 | 16–19 位 | **Luhn（MOD 10）校验** | `[BANK]` |

候选 token 的边界：`(?<![0-9A-Za-z])(\+?\d{11,19}[Xx]?)(?![0-9A-Za-z])`——
前后不能紧邻 ASCII 字母/数字（`_`、中文标点、空白都算边界），因此 20 位以上的长串整体不匹配。
判定优先级固定为 **身份证 → 手机号 → 银行卡**，同一段数字只替换一次，不会二次替换。

两种输入形态都覆盖：

- **全角数字**：扫描前做 1:1 宽度折叠（`１３８…` → `138…`，`＋` → `+`，含全角空格），
  替换仍回填到原文字符区间，因此非 PII 的全角字符保持原样。
- **分组写法**：`138 1234 5678`、`138-1234-5678`、`6222 0212 3456 7890` 会先按分隔符
  （空格 / 不换行空格 / 连字符）拼接再校验，每组至少 3 位（避免把 `2026 11 05` 当号码）。

---

## 4. 配置项

安装后改 profile 里该行的 `config:`（见第 5 节），键名与默认值：

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 总开关；`false` 时插件只挂载不注册监听 |
| `redactIdCard` | `true` | 身份证 |
| `redactPhone` | `true` | 手机号 |
| `redactBankCard` | `true` | 银行卡 |
| `allowLegacyId15` | `false` | 15 位旧证（无校验位，精度较低，默认关） |
| `strictIdChecksum` | `true` | 身份证是否强制校验位。**默认 true = 严格**：只拦校验位正确的证件；设 `false` 才启用兜底（校验位错的 18 位也标 `[ID]`） |
| `allowCountryCode` | `true` | 允许 `86` / `0086` / `+86` 前缀 |
| `requireLuhn` | `true` | 银行卡必须过 Luhn；关掉=召回优先（误报上升） |
| `minBankCardLength` | `16` | 银行卡最短位数 |
| `maxBankCardLength` | `19` | 银行卡最长位数 |
| `redactInjectedContext` | `false` | 是否也脱敏注入的非用户消息（记忆召回等）。宿主内置 `runtime-context` 快照无论如何改不动（见第 1 节） |
| `failClosed` | `false` | 引擎异常时：`false`=原文放行并告警；`true`=拒绝该步（`reject`），不让未脱敏消息出去 |

类型不符或未知键**保留默认值**，不会因为写错一个键就静默关掉脱敏。

---

## 5. 注册到 DSH

> 推荐用宿主自己的安装入口，**不要手写** `~/.dsh/profiles/web/cordis.patch.yml` 或 profile 的
> `package.json`：那两份文件属于用户、混有其它插件的 `insert` 行与注释，手工合并会被下一次
> 管理器操作覆盖，也不属于本 bundle。

### 方式 A（推荐）：`plugin_manager install_bundle`

在 DSH 会话里让 Agent 执行（或你直接在插件管理器界面里选本地目录）：

```
plugin_manager
  action: install_bundle
  target: ~/Documents/deepseek-harness/default-workspace/pii-redactor
```

它完成三件事：把包 `link:` 进 profile 的依赖 → 把 bundle 加进 `package.json` 的
`dsh.profile.bundles` → 热重载生效。返回里看 `application: applied`、`warnings: []`
（`restart-required` 表示需要重启）。
**首次安装即生效，影响该 profile 下所有会话**。根上下文监听天然覆盖子代理（宿主作用域过滤允许
祖先上下文收到后代事件），但这一条属于“装好后应用一次子代理会话复核”的项，别只凭代码假设。

### 方式 B：调参与确认

安装**不会**往 profile 的 `cordis.patch.yml` 里写行——行在 bundle 自带的
`cordis.patch.yml` 里，profile 只记录“启用了这个 bundle”。要调参，就在 profile 的
`cordis.patch.yml` 末尾追加一条 **同名 id 的覆盖**（Loader 语义：同 id 无 `insert` 即替换该行，
`config` 是整体替换而非深合并，所以要写全你要的键）：

```yaml
- id: pii-redactor
  name: '@local/dsh-pii-redactor'
  config:
    enabled: true
    redactIdCard: true
    redactPhone: true
    redactBankCard: true
    allowLegacyId15: false
    strictIdChecksum: true
    allowCountryCode: true
    requireLuhn: true
    minBankCardLength: 16
    maxBankCardLength: 19
    redactInjectedContext: false
    failClosed: false
```

改完不用重启（Loader 会重载该行）；`id` 不要改。也可以先 `plugin_manager list_bundles`
确认 `@local/dsh-pii-redactor` 在启用列表里。

---

## 6. 验证（按顺序做，别跳）

**① 静态**

```bash
cd ~/Documents/deepseek-harness/default-workspace/pii-redactor
node --check index.js
node --test          # 预期 80 个测试：79 passed / 1 todo / 0 failed
```

**② 组合生效**

```bash
dsh --profile web --dump-config | grep -A13 pii-redactor   # 需要 dsh 在 PATH 上
```

应能看到 `name: '@local/dsh-pii-redactor'` 与该行 config。

**③ 运行实测**（用**现造的合成号码**，不要用真实证件）

新开一个会话，发送：

```
测试：手机号 13900001111，卡号 6222021234567894
```

预期：

1. 宿主终端出现**一行黄色**日志：
   `[pii-redactor] 已拦截并替换 2 条敏感信息（手机号 1 / 银行卡 1），本步已脱敏放行。 turn=1 step=1`
   （示例里的卡号 `6222021234567894` 已算好 Luhn；自己造值时要过 Luhn 才会被识别）
   （非 TTY / `NO_COLOR` 时同一行不带颜色码）
2. 模型的回显/回答里看到的是 `[PHONE]` 与 `[BANK]`，不是原号码；
3. 该会话 JSONL 中，`user/message` 事件正文是占位符；`agent/inbox/spliced` 仍是原文（本地留痕，不外发）。

**④ 边界回归**：发一条 `order 20261105203045 ip 10.0.0.1`，应**不**出现任何替换与告警。

---

## 7. 回退（任选，按影响面从小到大）

| 动作 | 做法 | 效果 |
|---|---|---|
| 临时停用 | config 里 `enabled: false` | 立即停止脱敏，包仍装着 |
| 插件级停用 | `plugin_manager set_plugin`（清 `pii-redactor` 行） | 同上，走管理器 |
| 彻底移除 | `plugin_manager remove_bundle` | 卸载包并移除 patch 行 |
| 应急 | `cp` 快照回滚 profile 的 `cordis.patch.yml` | 仅在前者都不可用时 |

回退后建议复跑第 6 节 ③，确认日志不再出现。

---

## 8. 已知取舍

- **精度优先**：`requireLuhn: true` 会漏掉少数不遵循 Luhn 的卡（历史/特殊 BIN）。若要“宁可错杀”，
  设 `requireLuhn: false`，代价是随机 16–19 位数字约有 1/10 会被替换。
- **默认严格（v0.2.1 起）**：真实签发的证件校验位必然正确，所以严格模式对真实证件零漏检；被改动、抄错、OCR 错的证件号会放行——这是明确取舍，不是缺陷。若现场更怕漏检，把 `strictIdChecksum` 设成 `false` 启用兜底，代价是随机 18 位数字约 0.035% 误标。
- **15 位旧证默认关**：没有校验位，误报率高于 18 位；老数据场景请自行打开。
- **分隔符仅限空格 / 不换行空格 / 连字符**：斜杠、点号等其它分隔写法不匹配（避免把日期、版本号吞掉）。
- **默认失败策略是 fail-open**：引擎若抛异常，消息按原文放行并打一条黄色告警
  （`脱敏失败，消息按原文放行`），避免把用户消息静默吞掉。高敏部署把 `failClosed` 设为 `true`
  即可改为 fail-closed（返回 `reject`，该轮被拦截、消息不发出）。
- **分组写法会让长数字更“像”卡号**：`2026 1105 2030 4512` 这类 4×4 分组的 16 位数字，
  若恰好过 Luhn（约 1/10）会被替换成 `[BANK]`；这是为了覆盖银行短信/对账单格式付出的代价。
- **两段 PII 无分隔粘连会被跳过**：`<身份证><手机号>` 首尾相接时是一个超长数字串，超出候选边界。
- **全角折叠是等长的**：折返只影响扫描副本，输出仍用你原文的字符（非 PII 的全角数字不被改写）。

---

## 9. 与 PII 红线的对齐

本插件解决的是**外发面**（模型 API 看到什么），不改变**落盘面**（本机会话文件仍留原文）。
按团队红线 `_artifacts/pii-incident-20261105/AI-FORENSICS-REDLINES.md` 的口径，正确说法是：

> 已具备“请求发出前把可格式化 PII 换成占位符”的本地拦截能力；但**证件号仍属“入口不入”**——
> 拦截是兜底，不是许可。姓名/住址/单位等语义型 PII 没有任何自动网。

建议同时保持：输入侧纪律（证件号不贴入对话）+ 记忆插件的捕获开关按需收敛。

---

## 10. 验证状态

| 项 | 状态 |
|---|---|
| 引擎单测（23 条：校验位、兜底、边界、误报、幂等、全角、分组） | ✅ 已跑通 |
| 插件接线单测（8 条：改写、字段保留、reject 直通、fail-open/fail-closed） | ✅ 已跑通 |
| 独立对抗性审查（48 条，1 条 todo=已知结构限制） | ✅ 已跑通；4 项必修已修（见 `test/audit-report.md` 复核节） |
| `index.js` 语法检查 | ✅ |
| 安装进 `web` profile（v0.1.1，`application: applied`，`warnings: []`） | ✅ 2026-11-12 |
| 真实会话链路（子代理 prompt 含合成 PII，实跑） | ✅ 2026-11-12：子代理回显 `[PHONE]`/`[BANK]`/`[ID]`；子会话日志 `user/message` 含占位符、**0 处**原文，`agent/inbox/spliced` 含原文 1 处 |
| 根上下文覆盖子代理 | ✅ 同上（该次实测走 subagent 会话） |
| 黄色警告行目视 | ⏳ 需看宿主终端（单测已覆盖 warn 路径与“日志不含原值”）；预期形如 `[pii-redactor] 已拦截并替换 3 条敏感信息（…）` |
| 插件管理器内标题/描述/图标 | ⏳ 需在 GUI 插件详情页目视确认 |
