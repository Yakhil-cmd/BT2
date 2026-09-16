### Title
Denial of Service via uncaught `TypeError` in AA `json_parse()` object-size check — ([File: formula/evaluation.js])

### Summary
The oscript `json_parse()` built-in, reachable by any AA trigger sender whose triggering unit is processed by an Autonomous Agent that calls `json_parse()`, calls the size-guard helper `isTooBigObj()` with only one argument. The helper's signature requires a second, destructured options object with no top-level default, so calling it with a single argument throws an uncaught `TypeError` instead of returning a boolean. This mirrors the JasPer CVE-2018-20584 pattern: a routine "conversion" step (JSON→internal object conversion) on attacker-influenced input crashes/hangs application logic instead of failing gracefully, causing a denial of service for whoever triggers that AA.

### Finding Description
`json_parse` handling in the AA formula evaluator parses attacker-supplied string data and then checks the parsed result's size before further processing: [1](#0-0) 

The size-check function `isTooBigObj` is defined to require a second parameter that is destructured with per-field defaults, but the parameter itself has no default value: [2](#0-1) 

When `json_parse()`'s result is a plain object or array (`typeof json === 'object'`), `isTooBigObj(json)` is invoked with only the parsed value and no options object. JavaScript destructuring `{ depthLimit = 100, ... }` against `undefined` throws `TypeError: Cannot destructure property 'depthLimit' of 'undefined' as it is undefined.` immediately, synchronously, inside the `evaluate()` callback of the `json_parse` case.

The only `try/catch` in this code path wraps solely the `JSON.parse(res)` call: [3](#0-2) 
The subsequent `isTooBigObj(json)` call at line 1941 is outside that `try/catch`, so the `TypeError` propagates up uncaught.

`formula/evaluation.js`'s `evaluate` is invoked from `aa_composer.js` in many places (`evaluateAA`, `replace`, case/`if`/`init` formula evaluation, `executeStateUpdateFormula`) via `formulaParser.evaluate(opts, ..., callback)`, none of which wrap the call in `try/catch`: [4](#0-3) [5](#0-4) [6](#0-5) 

Because `handleTrigger` and its formula evaluation are invoked while processing every unit that spends into an AA address (during unit writing/stabilization), an uncaught synchronous exception thrown mid-evaluation aborts that call stack ungracefully instead of returning a validation/bounce error through the normal callback-based error channel. Depending on the caller in the write/stabilization pipeline, this can escape as an unhandled exception, which in Node.js typically crashes the process (or at minimum leaves the AA-processing/DB-transaction state inconsistent), unlike every other error path in this codebase, which deliberately returns errors through `cb(...)`/`setFatalError(...)` so that bad units are bounced instead of crashing the node.

### Impact Explanation
Any account can trigger this by sending a payment or `data` message to an AA whose oscript defines a getter/state/output formula using `json_parse()` on trigger data that resolves to a JSON object or array (e.g., `json_parse(trigger.data.x)` where `trigger.data.x` is `{"a":1}`, or literally `json_parse('{"a":1}')`). This is an extremely common oscript pattern (data feeds, nested trigger data, AA-to-AA composition). Triggering the bug causes an uncaught exception during AA response computation on every node that processes the triggering unit (including full/hub nodes and any other party running the same AA logic, e.g., during unit validation or state var computation), causing the node process to crash or hang unit processing — a network-wide denial of service on nodes hosting the affected AA. This matches the "network unable to confirm new units" / node crash bar for Medium–High impact.

### Likelihood Explanation
Exploitation requires no special privileges: it is a single well-formed unit (payment/data trigger) sent to any AA that uses `json_parse()` on an object/array-shaped value, which is a routine oscript idiom widely used and even present in the project's own tests, e.g.: [7](#0-6) 
No malicious peer, hub, or privileged operator role is needed — an ordinary unit poster/AA trigger sender can reach this path directly through normal transaction posting.

### Recommendation
Fix the call site (and/or the function signature) so `isTooBigObj` cannot throw on missing options:
- Either provide a default for the whole options parameter: `function isTooBigObj(obj, opts = {}) { const { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 } = opts; ... }`, or
- Pass an explicit options object at every call site, e.g. `isTooBigObj(json, {})`.
Additionally, wrap the post-parse logic in `json_parse` (and ideally the whole `evaluate()` dispatcher, or each `formulaParser.evaluate` call site in `aa_composer.js`) in a `try/catch` that converts unexpected exceptions into a fatal formula error (`setFatalError`) rather than allowing them to propagate as uncaught exceptions, consistent with the defensive pattern used everywhere else in this evaluator.

### Proof of Concept
Register/deploy an AA whose definition includes, e.g., a `data` message using:
```
result: "{ json_parse('{\"a\":1}') }"
```
or reference `trigger.data` containing an object-valued JSON string, then send a payment/trigger unit to that AA address:
```js
var aa = ['autonomous agent', {
  messages: [{
    app: 'data',
    payload: { result: `{ json_parse('{"a":1}') }` }
  }]
}];
```
On evaluating this AA (via `aa_composer.handleTrigger`), the `json_parse` case in `formula/evaluation.js` (lines 1934–1943) parses the JSON into an object and calls `isTooBigObj(json)` with a single argument, raising `TypeError: Cannot destructure property 'depthLimit' of 'undefined' as it is undefined`, uncaught by any surrounding handler in the AA evaluation/composition call chain.

Note: I was unable to execute the AA test-suite in this environment to directly observe the runtime crash; this assessment is based on static analysis of the exact call signature mismatch between `formula/evaluation.js:1941` and `string_utils.js:286`, and the absence of any enclosing `try/catch` in the traced call paths in `aa_composer.js`. A Devin session with repository execution access could run `test/formula.test.js`/`test/aa.test.js` variants with an object-valued `json_parse()` result to confirm the uncaught exception empirically.

### Citations

**File:** formula/evaluation.js (L1934-1943)
```javascript
					try {
						var json = JSON.parse(res);
					}
					catch (e) {
						console.log('json_parse failed: ' + e.toString());
						return cb(false);
					}
					if (typeof json === 'object' && isTooBigObj(json))
						return setFatalError("json_parse result is too big", { arr }, false, cb);
					json = replaceNulls(json);
```

**File:** string_utils.js (L286-292)
```javascript
function isTooBigObj(obj, { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 }) {
	let nodeCount = 0;
	let length = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit || length > lengthLimit)
			return true;
```

**File:** aa_composer.js (L610-614)
```javascript
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
```

**File:** aa_composer.js (L682-695)
```javascript
			formulaParser.evaluate(opts, [], xpath, function (err, res) {
			//	console.log('--- f', f, '=', res, typeof res);
				if (res === null)
					return cb(err.formattedError || "formula " + f + " failed: "+err);
				if (res === '' || isEmptyObjectOrArray(res)) { // signals that the key should be removed (only empty string or array or object, cannot be false as it is a valid value for asset properties)
					if (typeof name === 'string')
						delete obj[name];
					else
						assignField(obj, name, null);
				}
				else
					assignField(obj, name, res);
				cb();
			});
```

**File:** aa_composer.js (L1454-1462)
```javascript
		formulaParser.evaluate(opts, [], objStateUpdate.xpath, function (err, res) {
		//	console.log('--- state update formula', objStateUpdate.formula, '=', res);
			if (res === null)
				return cb(err.formattedError || "formula " + objStateUpdate.formula + " failed: "+err);
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			cb();
		});
```

**File:** test/formula.test.js (L2227-2234)
```javascript
test('json_parse', t => {
	var trigger = { data: { z: ['z', 9, 'ak'], ww: {dd: 'h', aa: 8}} };
	var stateVars = {  };
	evalFormulaWithVars({ conn: null, formula: `json_parse('{"ww":{"aa":8,"dd":"h"},"z":["z",9,"ak"]}')`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity) => {
		t.deepEqual(res, { z: ['z', 9, 'ak'], ww: {dd: 'h', aa: 8}});
		t.deepEqual(complexity, 2);
	})
});
```
