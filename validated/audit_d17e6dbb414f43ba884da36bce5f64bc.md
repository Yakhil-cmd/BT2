### Title
Unbounded formula-string length in AA `data_feed` message validation enables CPU-exhaustion DoS - (File: aa_validation.js)

### Summary
The `gradio-app/gradio` report describes an unauthenticated DoS caused by accepting an excessively large, unvalidated field (a filename) and doing expensive processing on it before any size check. The reachable analog in `ocore` is in AA definition validation, where the `data_feed` message's `feed_name` and feed `value` fields skip the fixed-length checks (`MAX_DATA_FEED_NAME_LENGTH` / `MAX_DATA_FEED_VALUE_LENGTH`) whenever the field is recognized as a formula (wrapped in `{...}`), letting an attacker embed an arbitrarily large string (bounded only by `MAX_UNIT_LENGTH`, 5 MB) that is fed to the formula parser.

### Finding Description
In `aa_validation.js` `validatePayload` for `case 'data_feed'`, the length checks are only applied to the non-formula branch: [1](#0-0) 
Specifically:
- `feed_name`: `getFormula(feed_name)` is computed first; the `MAX_DATA_FEED_NAME_LENGTH` check at line 98 only runs `if (feed_name_formula === null)` — i.e. only when the string is *not* recognized as a formula.
- `value`: the same pattern applies — `MAX_DATA_FEED_VALUE_LENGTH` is only enforced `if (value_formula === null)`.

`getFormula` itself (in `formula/common.js`) merely checks that the string starts with `{` and ends with `}` and does no length validation: [2](#0-1) 

Because any string of the form `{` + huge_payload + `}` satisfies `getFormula`, an attacker can set `feed_name` or `value` to a multi-megabyte string (limited only by the overall unit size limit `MAX_UNIT_LENGTH = 5e6` bytes) and bypass the 64-character caps that are meant to bound cost. This formula content is later parsed with the Earley/nearley-based `oscript` grammar (`formula/validation.js` `exports.validate`, which calls `nearley.Parser.feed(formula)`): [3](#0-2) 
Earley parsing is worst-case cubic (or worse for ambiguous/backtracking-heavy grammars) in input length, so feeding it a several-megabyte crafted string can consume disproportionate CPU/memory compared to the tiny, capped inputs the length limits were designed to allow, in the same class as the reported "large filename" DoS: an untrusted field is not size-limited before being fed to expensive processing.

By contrast, other AA fields that accept a formula (e.g., `attestors`, generic `payload`, `init`) never impose a length cap either, but `data_feed`'s `feed_name`/`value` are the fields explicitly guarded elsewhere (constants `MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH`, both 64) — this is the strongest evidence the omission for the formula branch is an oversight rather than an intended unlimited-size code path: [4](#0-3) 

The same unguarded pattern exists for the plain (non-AA) `data_feed` message validation path in `validation.js`, though there the payload is not string-formula-annotated at that stage, so the AA definition path is the primary reachable trigger for the bypass.

### Impact Explanation
Any unprivileged user who posts an AA definition unit can embed one or more `data_feed` messages with formula-wrapped `feed_name`/`value` fields sized close to the unit size limit. Whenever this AA definition is validated (on initial posting and again whenever the AA is later referenced/executed and its definition is re-validated/parsed by any full node), the node performs Earley-parser work proportional to a super-linear function of input length on attacker-controlled content. Multiple such large fields, or multiple messages within `MAX_MESSAGES_PER_UNIT` (128), amplify the effect. This can degrade block/unit-processing latency and node responsiveness across the network as every node that validates and re-derives the AA definition performs the same expensive parse, which maps to "a network unable to confirm new units in a timely manner" for nodes handling the burst.

### Likelihood Explanation
Likelihood is Medium-High for a DoS-class finding: no privileges beyond the ability to broadcast a unit are required, the unit-size limit (5 MB) is large enough to construct a costly payload, and the vulnerable code path (`getFormula` bypass of the length caps) is unconditionally reachable in `validateAADefinition`, which runs on every AA definition posted to the network.

### Recommendation
Enforce `MAX_DATA_FEED_NAME_LENGTH` / `MAX_DATA_FEED_VALUE_LENGTH` (or a new, generous but bounded formula-length constant) unconditionally in `aa_validation.js`'s `data_feed` handling, regardless of whether `getFormula` recognizes the value as a formula, before any parsing occurs. More generally, introduce a maximum length check on every string field accepted by `getFormula()` calls throughout `aa_validation.js` (attestors, payload, init, etc.) prior to invoking `formulaValidator.validate`, so that formula-annotated fields cannot grow unbounded up to `MAX_UNIT_LENGTH`.

### Proof of Concept
1. Construct an AA definition unit containing a message: `{app: 'data_feed', payload: {"{" + "A".repeat(4_000_000) + "}": 1}}` (a `feed_name` that is a ~4 MB string wrapped in braces so `getFormula` treats it as a formula).
2. Ensure total unit size stays under `MAX_UNIT_LENGTH` (5 MB) so the unit itself passes the outer size check in `validation.js`.
3. Post/broadcast the unit for AA-definition validation. `aa_validation.js` `validatePayload` (`case 'data_feed'`) accepts the huge `feed_name` because `feed_name_formula !== null` skips the `MAX_DATA_FEED_NAME_LENGTH` check.
4. When this formula string is subsequently parsed (`formula/validation.js` `exports.validate` → `nearley.Parser.feed`), observe disproportionate CPU time/memory versus a length-capped 64-character formula, repeatable by any node validating or re-processing this AA definition.

### Citations

**File:** aa_validation.js (L92-120)
```javascript
				case 'data_feed':
					if (!isNonemptyObject(payload))
						return cb2("data feed payload must be non-empty object or formula");
					for (var feed_name in payload) {
						var feed_name_formula = getFormula(feed_name);
						if (feed_name_formula === null) {
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
						var value = payload[feed_name];
						if (typeof value === 'string') {
							var value_formula = getFormula(value);
							if (value_formula === null) {
								if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
									return cb2("value " + value + " too long");
								if (value.indexOf('\n') >= 0)
									return cb2("value " + value + " of feed name " + feed_name + " contains \\n");
							}
						}
						else if (typeof value === 'number') {
							if (!isInteger(value))
								return cb2("fractional numbers not allowed in data feeds");
						}
						else
							return cb2("data feed " + feed_name + " must be string or number");
					}
					cb2();
```

**File:** formula/common.js (L82-93)
```javascript
function getFormula(str, bOptionalBraces) {
	if (bOptionalBraces)
		throw Error("braces cannot be optional");
	if (typeof str !== 'string')
		return null;
	if (str[0] === '{' && str[str.length - 1] === '}')
		return str.slice(1, -1);
	else if (bOptionalBraces)
		return str;
	else
		return null;
}
```

**File:** formula/validation.js (L249-266)
```javascript
	var parser = {};
	try {
		if(cache[formula]){
			parser.results = cache[formula];
		}else {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			if(formulasInCache.length > cacheLimit){
				var f = formulasInCache.shift();
				delete cache[f];
			}
			formulasInCache.push(formula);
			cache[formula] = parser.results;
		}
	} catch (e) {
		console.log('==== parse error', e, e.stack)
		return callback({error: 'parse error', complexity, errorMessage: e.message});
	}
```

**File:** constants.js (L53-54)
```javascript
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
```
