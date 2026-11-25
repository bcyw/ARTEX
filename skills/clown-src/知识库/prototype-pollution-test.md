> 短表「PP 打到模板 RCE」在后半「来源专题：prototype-pollution-advanced」下。先确认属性污染及真实消费者，再按版本/配置选择候选；JSON 能合并或出现库名不等于链可达。延迟消费见 [解释执行](el-injection-test.md)。

# prototype-pollution


# 来源专题：prototype-pollution

# Prototype Pollution

## 0. QUICK START

### Client-side first probes

```text
#__proto__[pp_probe_7f]=marker
#constructor[prototype][pp_probe_7f]=marker
```

Use one unique, harmless marker when a normal operation supports a specific fragment/query parsing and property-write hypothesis. Record that operation under the same identity, then inspect the relevant object/prototype before and after the candidate input in the **same realm**. Text reflection or a console value alone does not identify a prototype write; script execution is a separate consumer question.

### Server-side first probes（JSON / form）

```json
{"__proto__":{"polluted":true}}
```

```json
{"constructor":{"prototype":{"polluted":true}}}
```

First locate a reachable parser/merge/assignment and an observation tied to its object or consumer. Compare a normal request, an ordinary-field control and one candidate input under the same identity; a marker echoed as an own field is not shared-prototype pollution. Follow-up responses can test scope only when their consumer and request/worker association are understood (see §3).

### Candidate selection

Names such as `lodash.merge`, `deep-extend`, `hoek.applyToDefaults`, `qs` or `query-string` help locate code, not rank exploitability. Use actual input handling, controlled differences or available implementation/configuration evidence to form one parser/write hypothesis, then choose a discriminating observation. Source access is not mandatory, but a dependency name or a parsed nested object alone does not establish a prototype write.

---

## 1. MECHANISM

**Prototype chain**: an ordinary property lookup can follow `[[Prototype]]` when an own property is absent, ending at `null`; not every object chain contains `Object.prototype`. Identify the actual object, own properties and prototype chain before interpreting a result.

**`__proto__`**: a member produced by ordinary `JSON.parse` is not by itself a prototype write. A later assignment, path traversal or merge may handle that key differently. Distinguish an ordinary data member, a changed prototype of one target object and a write to a shared prototype; do not treat JavaScript object-literal syntax as an interchangeable JSON transport test.

**`constructor.prototype`**: a candidate path only if the actual traversal resolves these components to a prototype and permits the write; own fields, path handling and restrictions can prevent that. Example input shape:

```json
{"constructor":{"prototype":{"polluted":1}}}
```

This is not equivalent to `__proto__`. Choose between them using evidence about key parsing, filtering and traversal; lack of a signal is not a reason to try both unconditionally.

**Core issue**: an uncontrolled prototype write matters when a reachable consumer reads the affected property across a trust boundary. Its scope may be one object, one realm or shared server state; neither a global effect nor a dangerous gadget follows automatically.

2026-11-25 semantic check: [ECMAScript JSON.parse](https://tc39.es/ecma262/multipage/structured-data.html#sec-json.parse). The current specification distinguishes JSON parsing from object-literal evaluation; application revivers/parsers and later writes still require inspection. This is a language reference, not evidence about an installed library or a tested target.

---

## 2. CLIENT-SIDE DETECTION

### URL fragment

```text
https://app.example/page#__proto__[pp_probe_7f]=marker
```

Requires the observed router/analytics path to parse this syntax and write the resulting keys. Reflection, an ignored fragment or an ordinary own-field update are competing explanations.

### `constructor.prototype` path

```text
#constructor[prototype][pp_probe_7f]=marker
```

### DOM / attribute injection ideas

If a proven property-writing path feeds a specific DOM configuration reader, `src` is one candidate to trace with an owned harmless resource:

```text
__proto__[src]=/owned-test-resource
```

An event-like name such as `onerror` is only another candidate name. Establish whether the consumer accepts the value, reads it as inherited state and assigns/evaluates it; a JSON string does not become a callable merely because of the key name.

**Verification**: capture the marker's property descriptor and the relevant object's prototype before/after the controlled action in the same page realm, distinguishing own-field changes from prototype changes. A new realm is a separate baseline, not a view of the previous realm's memory: absence there does not refute the earlier write, and a repeated effect needs its own input/initialization attribution. Account for frame/worker boundaries, extensions and DevTools writes; do not manually set the prototype and attribute that change to the application.

The [ECMAScript realm model](https://tc39.es/ecma262/multipage/executable-code-and-execution-contexts.html#sec-code-realms) associates intrinsic objects and global state with a realm (checked 2026-11-25). No browser or target scenario was executed here.

---

## 3. SERVER-SIDE DETECTION (Express / Node, black-box)

For these historical property names, distinguish two hypotheses: input reaches a prototype write, and a later consumer reads that property. Choose an observation that separates the relevant hypothesis from ordinary data/configuration handling; JSON decoding, nested parsing or an Express/Node fingerprint alone proves neither. Keep the experiment harmless and reversible in the permitted environment, with valid normal operation and identity.

| Candidate input | Required read and competing explanation |
|----------------------|----------------|
| `{"__proto__":{"parameterLimit":1}}` | Does the actual parser read an inherited limit? Existing limits, rejection and body format can also drop parameters. |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | Does this parser consume that option? Prefix handling may be normal parsing behavior. |
| `{"__proto__":{"allowDots":true}}` | Does an inherited option affect this parser call? Dot expansion may already be configured or performed by another layer. |
| `{"__proto__":{"json spaces":" "}}` | Does this serializer integration read the property? Formatting may come from fixed settings, another worker or a proxy. |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | Does this CORS consumer read an inherited configuration? Normal CORS policy or direct header reflection can explain the response. |
| `{"__proto__":{"status":510}}` | Does this error/response path read the affected property? Validation errors or explicitly copied status fields are alternative causes. |

**Observation order**: normal request → one candidate → the same normal request/consumer, with request IDs and identity recorded. A clean follow-up can expose an effect but does not identify its cause alone. Workers, caches and shared configuration are competing explanations; connection reuse does not establish a shared worker. Stop at a specific blocker if the observation cannot be associated. A changed header/spacing/status is mechanism evidence at most until an actual trust-boundary impact is shown.

---

## 4. EXPLOITATION GADGETS

| Target / scenario | Payload or pattern | Notes |
|-------------|------------|------|
| **EJS** | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('COMMAND')"}}` | If template engine options like `escapeFunction` are read from polluted prototype, this may lead to RCE; strongly version/config dependent |
| **Timelion expression chain (CVE-2019-7609)** | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND")')` | Imported historical expression/PP candidate; actual plugin/version, property propagation and consumer remain prerequisites, not a compatibility promise |
| **Node `child_process`** | Candidate fields `shell`, `argv0`, `env`, `NODE_OPTIONS`, etc. | Trace actual option construction and the selected child-process call; see the runtime/configuration conditions below |
| **Generic constructor path** | `{"constructor":{"prototype":{"foo":"bar"}}}` | Alternative only if the parser/traversal accepts this path and reaches a prototype; filtering one key does not prove the alternative works |

**Chain evidence**: input → specific prototype write → reachable inherited-property read → bounded observed effect. Missing own-property checks alone do not establish RCE, SSRF or path traversal; the value and consumer must support that effect.

---

## 5. TOOLS

| Project | Purpose |
|------|------|
| **yeswehack/pp-finder** | Helps locate PP-prone merge points and patterns |
| **yuske/silent-spring** | Research and detection around prototype-pollution surfaces |
| **yuske/server-side-prototype-pollution** | Server-side PP testing suite/methodology |
| **BlackFan/client-side-prototype-pollution** | Browser-side PP cases and payloads |
| **portswigger/server-side-prototype-pollution** | Burp ecosystem extension / supporting material |
| **msrkp/PPScan** | Scanning/verification helper |

Prioritize use on **authorized** targets; automated tools can cause side effects on stateful applications.

---

## 6. DECISION TREE

```
Normal operation and identity valid?
├── NO → repair baseline / record blocker; not a mechanism negative
└── YES → input reaches a specific property-writing path?
    ├── UNKNOWN → locate parser, traversal and target object
    └── YES → distinguish own field / one-object prototype / shared prototype
        ├── Only reflection, error or unknown scope → discriminate before concluding
        └── Controlled prototype difference established
            ├── No reachable consumer → retain fact + consumer blocker
            └── Consumer reads the changed property
                ├── Normal feature / formatting only → no assumed security impact
                └── One bounded effect test + ordinary/non-triggered controls
                    → conclude only the observed trust-boundary impact
                      No automatic DoS, logic-impact or RCE report from PP alone
```

---


# 来源专题：prototype-pollution-advanced

# Prototype Pollution Advanced — RCE & Gadget Exploitation

### PP 打到模板 RCE（短表有指针）

认：已证实服务端属性/原型污染，并有具体模板、配置或子进程消费者读取该属性的证据。记录写入身份、属性、生命周期、消费者版本/配置、触发动作与结果；Node/Express 指纹或出现 `res.render` 不能替代这条链。

打：

1. 在获准受控环境确认无害属性差分，区分普通字段写入、实例原型变化与共享原型污染；观察范围和持久性，及时清理。
2. 沿实际属性读取查消费者：自己的属性、继承属性、默认值与空原型/复制行为不同。核对精确版本、选项、编译/缓存路径；用普通值与无触发对象区分“已写入”与“已消费”。
3. 只有消费者和危险调用前提成立，才选一条有界、非破坏性的效果验证。缺模板/子进程消费者即 blocker，不顺序轮换 EJS/Pug/`NODE_OPTIONS`。延迟触发按 [解释执行](el-injection-test.md) 的保存→触发→观察关联。

算成：将本次属性变化、实际触发和结果关联，并用普通值/未触发对照证明结果来自对应危险调用，而非原样回显、旧日志或缓存。标记或 `uid=` 字样本身不证明命令执行；只证实污染时保留为事实，按实际危害与标准卡收取，不补报 DoS/逻辑漏洞。

反例/缺口：只有展示变化不能证明服务端执行；没有对应消费者、配置不读取或版本不适用时不能沿旧链推断；请求后消失只限定生命周期，仍须区分同请求是否消费；渲染未运行或命中旧缓存则观察尚不完整。源码可达只缩小假设，不能代替本次触发效果。

下面及附件保留历史候选机制，不提供“库名→必成链”或成功率排名。路线与停止见 [技术路线研究](../rules/technical-route-research.md)。

## 1. SERVER-SIDE PP → RCE

### 1.1 Node.js child_process.spawn — Shell/ENV Injection

Historical candidate: a polluted option may influence a reachable child-process call. First establish the exact runtime, option construction/own-property handling, platform and trigger; absence of explicit options alone does not prove inherited control or execution.

Track `shell`, `env`, `argv0`, `execArgv` or other candidate options only when the application demonstrably propagates them to that call. Distinguish a top-level option from an environment entry, and inherited state from values copied by the application into own properties. A file-based candidate also needs a controlled readable file and an applicable runtime/platform; `/proc` paths are not portable.

2026-11-25 source check: [Node child-process API](https://nodejs.org/api/child_process.html) and [current main source](https://github.com/nodejs/node/blob/main/lib/child_process.js). The inspected `normalizeSpawnArguments` copies `options = { __proto__: null, ...options };`; `fork` has its own option normalization. This refutes an unconditional “missing options inherits the prototype and executes” rule, not every possible application-level propagation. Main is mutable and not a target version; no target or representative local application was tested.

### 1.2 EJS (Embedded JavaScript Templates)

`outputFunctionName` is a historical option-to-generated-source candidate, not an all-version chain. The official EJS v3.1.10 source checks it against a JavaScript identifier pattern and throws `outputFunctionName is not a valid JS identifier.` for invalid names; it also validates `destructuredLocals`. A library fingerprint or a merge alone therefore cannot establish code injection. Trace the actual option-copying, validation and compilation path before choosing a probe.

2026-11-25 source check: [EJS v3.1.10 compiler](https://github.com/mde/ejs/blob/v3.1.10/lib/ejs.js). This pinned version is a counterexample to the old “all versions” claim, not a claim that every other option/version is safe. No target or representative local application was tested.

### 1.3 Pug (formerly Jade)

`block`, node `type`/`val`, `self` and debug metadata are historical candidates for studying AST/option consumption. Distinguish text buffering from code generation, own fields from inherited defaults, and a normal compile error from a dangerous effect. Do not assume that an arbitrary `Text.val` is emitted as executable JavaScript.

2026-11-25 source check: [Pug code generator](https://github.com/pugjs/pug/blob/master/packages/pug-code-gen/index.js), mutable master with distinct node visitors (`visitText` calls `buffer`). This only identifies the code path to inspect; target release, parser/transforms, options and inherited reads remain unverified. No target or representative local application was tested.

### 1.4 Handlebars

Historical AST/option candidates for Handlebars; first prove that the exact installed compiler or runtime reads the controlled properties in this call:

```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "PathExpression", "original": "constructor.constructor('return process.mainModule.require(`child_process`).execSync(`id`)')()","parts": ["constructor","constructor"]}, "params": [], "hash": null}]}}
```

Another historical option candidate (not a bypass guarantee):

```json
{"__proto__": {"allowProtoMethodsByDefault": true, "allowProtoPropertiesByDefault": true}}
// Then use {{#with this as |obj|}}{{obj.constructor.constructor "return process.mainModule.require('child_process').execSync('id')"}}{{/with}}
```

### 1.5 Nunjucks

Historical AST candidate; requires a reachable compiler/transform consuming these properties. A loaded Nunjucks dependency is insufficient.

```json
{"__proto__": {"type": "Code", "value": "global.process.mainModule.require('child_process').execSync('id')"}}
```

### 1.6 Express res.render (Generic)

For an Express render path, trace how the actual view engine receives locals and options and whether inherited properties survive. The historical `view options` candidate below is not generic across engine, integration or version:

```json
{"__proto__": {"view options": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}}
```

---

## 2. CLIENT-SIDE PROTOTYPE POLLUTION

### 2.1 jQuery Gadgets

`$.extend(true, {}, userInput)` is a historical merge candidate, not proof of a vulnerable installed implementation. First trace the accepted keys, actual target and prototype changes. Then independently locate an inherited-property read in the application's DOM integration; a jQuery dependency or an HTML method name is insufficient.

```json
{"__proto__":{"pp_probe_7f":"marker"}}
```

This preserves the candidate input shape for a harmless write observation. `innerHTML`/`src` are downstream candidate names only after the actual configuration read is found; element creation or `appendTo` does not by itself prove either is read from the polluted prototype.

### 2.2 Lodash Gadgets

```javascript
// Candidate calls to inspect in the actual installed implementation:
_.merge({}, userInput)
_.defaultsDeep({}, userInput)
_.set(obj, path, value)  // establish accepted path and actual write target
```

`_.template` and `sourceURL` are historical consumer candidates, not a guaranteed next step from a merge. Determine whether the current options construction reads the inherited value and how validation/code generation handles it. A harmless marker in metadata or output is not execution; the attachment retains the historical construction for applicability review.

### 2.3 Script Gadgets in Frameworks

These imported names are lookup leads for actual application code, not verified framework-wide gadgets. Require a property write, an inherited read and the specific unsafe use; data binding or a documented template feature may explain the same visible output.

| Historical context | Consumer to locate | Candidate property | Evidence still required |
|---|---|---|---|
| jQuery | Application DOM integration | `innerHTML`, `src` | Actual inherited read and unsafe DOM use, not just element creation |
| Angular.js | Interpolation/compilation path | `__defineGetter__` | Actual use of the property and a boundary crossed, not a name match |
| Vue.js | Component/template path | `template`, `render` | Compiler/runtime mode, accepted value type and reachable use |
| Ember.js | Component rendering | Specific view property found in code | Exact read and output origin; no generic gadget assumed |
| Backbone.js | Application template integration | `sourceURL` | Actual option propagation and generated result |

### 2.4 DOM Property Pollution

```json
{"__proto__":{"src":"/owned-test-resource"}}
```

`src`, `href` and `action` remain candidate names for a **specific** configuration-to-element path. Inspect which object supplies the value and whether an own property, accessor, default or filtering prevents the hypothesized inherited read. An arbitrary property on `Object.prototype` does not imply every newly created DOM element consumes it. Use an owned inert destination to observe the selected path; URL assignment alone does not prove script execution or a different identity's impact.

---

## 3. DETECTION TECHNIQUES

### 3.1 Black-Box Server-Side Detection

1. Establish a normal operation, valid identity and a known observation endpoint/consumer. Use one unique harmless marker at the identified input position to test a specific parser/write hypothesis; compare an ordinary-field input and an unchanged request. A field reflected in the response may be ordinary data, not pollution.
2. Associate the changed behavior with the property write and consumer. For `status` or `content-type` candidates, compare raw responses and inspect whether the consumer reads inherited state, an explicitly copied field or fixed configuration. Do not select an arbitrary `/api/anything` and infer shared state from its error.
3. Historical `{"__proto__":{"toString":1}}` / `{"__proto__":{"valueOf":1}}` constructions can disrupt common methods and are not default probes. Consider them only in an explicitly permitted isolated, recoverable setting with a relevant read. A 500/crash is consistent with validation, a type mismatch, normal error handling or another failure; it does **not** prove that either prototype method was overwritten. Prefer harmless property/consumer observations; if the cause cannot be distinguished, record that uncertainty rather than a DoS or PP finding.

### 3.2 Black-Box Client-Side Detection

```javascript
// In the application's same realm, before the controlled action:
const probeKey = 'pp_probe_7f';  // use a unique marker absent in the baseline
const before = Object.getOwnPropertyDescriptor(Object.prototype, probeKey);
// Invoke the permitted input/consumer path, without writing the prototype in console.
const after = Object.getOwnPropertyDescriptor(Object.prototype, probeKey);
// Compare before/after and the actual application's object/prototype as well.
```

This observes only this realm's `Object.prototype`; absence there does not exclude a changed instance/custom prototype. A pre-existing descriptor or a changed value without an attributable input is not confirmation. Preserve the normal/ordinary-field control, execution context and descriptor provenance. Use a debugger at the actual write/read when available; replacing the built-in `__proto__` setter changes behavior and is not a transparent detector for all prototype writes.

### 3.3 Automated Tools

| Tool | Type | Purpose |
|---|---|---|
| **PPScan** | Burp Extension | Scans for server-side PP |
| **server-side-prototype-pollution** | Burp Extension (Gareth Heyes) | Advanced server-side PP detection with multiple techniques |
| **ppfuzz** | CLI | Fuzz for client-side PP via URL fragment/query |
| **ppmap** | CLI | Map client-side PP to known gadgets |

---

## 4. ALTERNATIVE PATH HYPOTHESES

Select an alternative only when parser/filter/traversal evidence predicts a different result. A rejected candidate does not justify spraying every syntax below; each change needs an observable distinction and a bounded stop condition.

### 4.1 constructor.prototype Path

```json
// Candidate A, when this key reaches a write:
{"__proto__": {"polluted": "yes"}}

// Candidate B, only when traversal resolves this alternative path:
{"constructor": {"prototype": {"polluted": "yes"}}}
```

### 4.2 Bracket Notation Variants

Requires this query parser to interpret brackets/nesting; the last shape additionally requires observed one-pass stripping before a later parse.

```
?constructor[prototype][polluted]=yes
?__proto__[polluted]=yes
?__pro__proto__to__[polluted]=yes   (if filter strips __proto__ once)
```

### 4.3 JSON Key Variations

These are distinct keys until the actual downstream transformation proves otherwise. A null character or spelling variation is not automatically an alias for `__proto__`.

```json
{"__proto__": {"a": 1}}
{"constructor": {"prototype": {"a": 1}}}
{"__proto__\u0000": {"a": 1}}
```

### 4.4 Key Distinction: Shallow vs Deep

Shallow versus deep describes copying, not a security verdict. `Object.assign` uses a property `Set` on the target; an applicable target setter can matter without recursive merging. Distinguish changing that target's prototype from writing to a shared `Object.prototype`, and inspect subsequent reads. Conversely, a deep merge that rejects the relevant path is not vulnerable merely because it is recursive.

2026-11-25 semantic check: [ECMAScript Object.assign](https://tc39.es/ecma262/multipage/fundamental-objects.html#sec-object.assign) and the [legacy `__proto__` accessor](https://tc39.es/ecma262/multipage/fundamental-objects.html#sec-object.prototype.__proto__). The accessor's presence/handling is a premise, not assumed for every runtime or object. These specification references correct the unconditional shallow-copy claim; no target/library application was tested.

---

## 5. EXPLOITATION FLOW

```
1. Locate an actual property-writing path (first topic, Section 0)
   └── Trace controlled keys through parsing, traversal/assignment and target identity

2. Confirm pollution:
   └── Unique harmless input + normal control → identify the changed object/prototype

3. Trace one actual property consumer, its version/configuration and trigger
   ├── Server template/compiler → Section 1, then save/trigger/observe
   ├── Child-process call → inspect actual option handling and runtime
   ├── Client DOM/template → Section 2; keep client/server effects distinct
   └── Unknown consumer → record the missing prerequisite, not a gadget sweep

4. Choose one bounded differential experiment with a non-triggered control
5. Attribute the observed effect to this property, trigger and consumer
6. Stop at the supported impact or blocker; a callback alone is not RCE
```

---

## 6. DECISION TREE

```
Confirmed prototype pollution?
│
├── Server-side or client-side?
│   │
│   ├── SERVER-SIDE
│   │   ├── Template engine in use?
│   │   │   ├── Known engine → inspect exact option/AST read and version (Section 1)
│   │   │   └── Unknown → locate the consumer or record blocker
│   │   │
│   │   ├── Reachable child_process call consumes a controlled option?
│   │   │   ├── YES → inspect runtime/platform and design one bounded test
│   │   │   └── UNKNOWN → collect call/option evidence, not blind option injection
│   │   │
│   │   └── No known consumer?
│   │       └── Retain the property-write fact and consumer blocker
│   │           Status/header candidates require a known read, not an automatic fallback
│   │
│   └── CLIENT-SIDE
│       ├── Actual jQuery/Lodash writing path → identify changed object in the same realm
│       ├── Actual DOM/template consumer → inspect property read and supported value type
│       └── Only library name / no consumer → locate evidence, not a gadget sweep
│
├── __proto__ keyword filtered?
│   └── Alternative path only if parser/filter evidence predicts a distinction (Section 4)
│
└── Not confirmed yet?
    └── Revisit baseline, competing explanations and observation; no automatic impact report
```

---

## 7. QUICK REFERENCE — CONSUMER QUESTIONS

- What exact property was changed, and on which object/prototype?
- Does the next consumer read an own property, inherited value or fixed default?
- Which version/options/transform make that read reachable?
- What action triggers it, under whose identity, and where is this result observed?
- Does the control exclude ordinary data binding, cached output and another request?

Use the relevant historical candidate only after these questions narrow the hypothesis; replacing `__proto__` with `constructor.prototype` without a parser/merge hypothesis is not new evidence.


---


## 附件：KNOWN_GADGETS

# Prototype Pollution — Known Gadgets Reference


## 1. EXPRESS TEMPLATE ENGINES (Server-Side → RCE)

### EJS (Embedded JavaScript)

| Candidate Property | Mechanism to inspect | Required consumer | Possible effect | Applicability |
|---|---|---|---|---|
| `outputFunctionName` | Option used in generated identifiers | Actual option propagation and compile path | Code generation only if constraints permit | v3.1.10 validates identifiers; see §1.2 |
| `destructuredLocals` | Names used for local declarations | Actual option propagation and compile path | Declaration change only if constraints permit | v3.1.10 validates names; no blanket 3.x claim |
| `escapeFunction` / `client` | Function/configuration consumed during compilation | Exact version, mode and inherited-property behavior | Determine from observed consumer | Historical candidates, not a version compatibility promise |

### Pug (formerly Jade)

| Candidate Property | Mechanism to inspect | Required consumer | Possible effect | Applicability |
|---|---|---|---|---|
| `block`, `type`, `val` | AST traversal and text/code handling | Actual parser/transform/compiler reading inherited fields | Determine from emitted result | No blanket 2.x–3.x claim; see §1.3 |
| `self`, `line`, `debug`, `compileDebug` | Option/debug metadata handling | Exact version, compile mode and output visibility | Error/context change is not automatically disclosure or execution | Historical candidates requiring source and runtime evidence |

### Other historical template candidates

These names retain research leads from the imported notes; their version ranges, API behavior and exploitability have not been revalidated. The old blanket version/impact table is removed. When an actual consumer is found, read that installed version's first-party documentation/source and check propagation before designing an experiment.

| Historical context | Candidate names to locate in actual code | Question, not an exploitation claim |
|---|---|---|
| Jade | `self`, `debug` | Does this compilation path consume the inherited option, and is any resulting output visible? |
| Handlebars | `type`, `program`, `helpers`, `allowProtoMethodsByDefault`, `allowProtoPropertiesByDefault` | Which compiler/runtime owns the property, and is the value data, AST or an actual callable? Do not infer the same behavior for Mustache. |
| Nunjucks | `type`, `value`, `autoesc` | Is the property read by the reachable transform/compiler or ignored as ordinary data? |
| Twig.js | `allowInlineIncludes`, `rethrow` | Does the exact version/options expose this path and an observable effect? |

---

## 2. LODASH

| Historical candidate | Construction to inspect | Required consumer/evidence |
|---|---|---|
| `sourceURL` | `"\u000ajavascript:alert(1)//"` | Exact option propagation, validation and generated source; a source label or marker is not XSS |
| `template` | Template string | Establish whether this property is read at all and whether it controls template source rather than data |
| `imports._.templateSettings.interpolate` | Custom regex | Resolve the actual settings/import object and value type; ordinary delimiter configuration is not code injection |

These imported candidates have no asserted compatible version range here. Candidate writing calls, distinct from the eventual consumer:
- `_.merge(target, source)` / `_.defaultsDeep(target, source)` — inspect accepted keys, own/inherited lookup and target; a deep merge alone is not a prototype-write proof.
- `_.set(obj, path, value)` / `_.setWith(obj, path, value)` — inspect actual path parsing/restrictions and the resolved write object.

```javascript
// Historical input + potential trigger, not a confirmation recipe:
_.merge({}, JSON.parse('{"__proto__":{"sourceURL":"\\u000ajavascript:alert(1)//"}}'));
// Only relevant if the above write and this inherited option read are established:
_.template('hello')();
```

---

## 3. JQUERY

| Historical candidate | Consumer to locate | Required evidence / counterexample |
|---|---|---|
| `innerHTML` | Application HTML/configuration path | Actual inherited read and unsafe interpretation; ordinary inert text output is different |
| `src`, `href` | Specific element/URL integration | Exact property source, element, URL handling and trigger; creation alone proves no inherited read or execution |
| `text` | Application text binding | Distinguish expected text display from a demonstrated cross-boundary effect; `.text()` is not itself an XSS conclusion |

Candidate writing calls are `$.extend(true, {}, userInput)` and application uses of `$.fn.extend()`. Trace their actual implementation and receiver; extending a particular library object is not automatically pollution of `Object.prototype`. The former blanket version/XSS mappings are not retained as compatibility claims.

---

## 4. ANGULAR.JS (1.x)

| Historical candidate | Path to inspect | Evidence still required |
|---|---|---|
| `__defineGetter__`, `toString`, `valueOf` | Actual interpolation/compilation read | Receiver, accepted value type and resulting operation; method names do not prove a callable injection |
| `$parent` | Actual expression/scope traversal | Whether controlled state changes a permitted lookup or crosses a trust boundary |
| `charset` | Application interceptor/configuration | Whether the property is consumed at all and what raw response changes |

The imported `{{constructor.constructor('alert(1)')()}}` expression is a historical candidate, not evidence that pollution disables a sandbox. Engine/version, expression context and the actual property-to-consumer path remain required; no affected version range is asserted here.

---

## 5. VUE.JS

| Historical candidate | Path to inspect | Evidence still required |
|---|---|---|
| `template` | Actual component option resolution and compiler | Inherited source accepted in this build/mode; ordinary template features are not PP proof |
| `render`, `staticRenderFns` | Actual rendering call and option construction | Supported value type and callable provenance; a JSON string/array does not itself supply functions |
| `compilerOptions` | Actual compilation path | The specific option is read and changes a relevant operation, not merely stored |

These names span historical integrations; establish the installed version/build and reachable consumer instead of assuming a Vue-wide chain.

---

## 6. WEBPACK

| Historical candidate | Consumer to inspect | Evidence still required |
|---|---|---|
| `output.library` | Actual configuration normalization and emitted wrapper | Inherited input survives validation and affects generated code, not just an allowed name |
| `output.auxiliaryComment` | Actual comment generation/escaping | A boundary-breaking generated result; changing comment text alone is insufficient |
| `devtool` | Actual build configuration | An unexpected cross-boundary capability; selecting a documented mode alone is not execution evidence |

These are build-configuration candidates requiring a reachable build consumer and an attributable artifact. A runtime dependency fingerprint does not establish that path; inspect any later artifact consumption separately. No blanket version or impact mapping is asserted.

---

## 7. FASTIFY

| Historical candidate | Consumer to inspect | Evidence still required |
|---|---|---|
| `reply.view` options | Actual template integration | Property propagation and observed effect; no assumed portability from EJS/Pug examples |
| `rewriteUrl` | Actual routing hook/configuration | A reachable read, supported value type and a demonstrated unauthorized route result |
| `schema` | Actual schema construction/validation | The inherited value changes enforcement for a controlled request; storage or a validation error is insufficient |

---

## 8. NODE.JS CORE

| Historical candidate | Required evidence before an experiment |
|---|---|
| `shell`, `argv0`, `execArgv` | Actual option construction, selected API, runtime/platform and a reachable call; no “All Node.js” compatibility claim |
| `env`, `NODE_OPTIONS` | Distinguish top-level options from entries of the actual child environment; verify what survives normalization and what the selected child consumes |
| `input`, `stdio` | Actual API supports and reads the option in this invocation; changing bytes/descriptors is not automatically execution |

See §1.1 for first-party sources and the current-source counterexample to universal prototype inheritance. Missing consumer/configuration evidence is a blocker.

---

## 9. MISCELLANEOUS LIBRARIES

### minimist (Argument Parser)

```bash
# Historical CLI input shape; only relevant if this input reaches the actual parser:
node app.js --__proto__.polluted yes
```

Inspect the installed parser/version, option handling and resulting object/prototype. This spelling alone does not establish a write, and no affected version cutoff is asserted here.

### yargs

Use the actual argument-parsing implementation as a candidate writing path; do not transfer minimist behavior or compatibility to it by analogy.

### qs (Query String Parser)

```
# Historical query shapes, contingent on actual nesting/dot handling:
?__proto__[polluted]=yes
?__proto__.polluted=yes
```

Distinguish accepted query syntax, ordinary nested data and a subsequent prototype write. Determine options and version from the actual call; no blanket historical cutoff is used here.

### destr (JSON Parser)

```javascript
destr('{"__proto__":{"polluted":"yes"}}')
// Candidate input only: inspect own member, instance prototype and later consumers.
```

### json5

```javascript
JSON5.parse('{"__proto__":{"polluted":"yes"}}')
// Candidate input only: distinguish parsed data from an actual prototype change.
```

---

## 10. GADGET SELECTION FLOWCHART

```
Confirmed property write and an actual consumer?
│
├── Server-side Node.js
│   ├── Express + template engine?
│   │   ├── Known engine → confirm property read, version, configuration and trigger
│   │   └── Unknown → locate consumer; do not default to EJS
│   │
│   ├── Fastify + point-of-view?
│   │   └── Trace integration-specific locals/options; do not assume gadget portability
│   │
│   ├── Reachable child_process consumer?
│   │   └── Inspect actual runtime/options/platform; no universal Node.js chain
│   │
│   └── No template / no child_process?
│       └── Locate another actual read or record consumer blocker; no assumed impact
│
├── Client-side JavaScript
│   ├── Reachable jQuery integration?
│   │   └── Confirm writing path and separate DOM read; names alone are insufficient
│   │
│   ├── Reachable Lodash integration?
│   │   └── Inspect actual merge/path handling and independent option consumer
│   │
│   ├── Reachable Angular/Vue component or compiler?
│   │   └── Inspect exact property, value type, context and trigger
│   │
│   └── No identified consumer?
│       └── Retain the observed fact; do not infer a generic DOM gadget
│
└── Build pipeline (CI/CD)
    └── Actual configuration read → controlled build → inspect attributable artifact
```
