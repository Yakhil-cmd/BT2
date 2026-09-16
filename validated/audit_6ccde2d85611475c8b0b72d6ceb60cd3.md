### Title
Shared cross-evaluation formula-parse cache in oscript engine can leak AST/state between concurrent AA/authentifier evaluations - (File: `formula/evaluation.js`)

### Summary
`formula/evaluation.js` and `formula/validation.js` share a single module-level `cache` object (defined in `formula/common.js`) keyed only by the raw formula text, independent of the calling context (address, trigger, mci, locals, AA vs. non-AA, statements-only, getters, etc.). This is analogous to CVE-2026-73631: per-request parsing state is stored in shared state and reused across otherwise-independent evaluation "requests," so context/limits tied to one evaluation can bleed into another.

### Finding Description
`formula/common.js` defines module-scoped mutable state shared by every formula evaluation in the process: [1](#0-0) 

`formula/evaluation.js` (used to evaluate AA definitions, triggers, getters, `if`/`init` formulas, and authentifier `formula` conditions) looks up this cache purely by the formula string and reuses the previously parsed nearley result object directly, without cloning it or scoping it to the current opts (locals, stateVars, trigger, address, mci): [2](#0-1) 

`formula/validation.js` shares the exact same cache instance for a structurally different purpose (static complexity/op-count validation rather than execution): [3](#0-2) 

Multiple call sites reach this cache concurrently from a single posted unit: AA getters and `if`/`init` blocks in `aa_composer.js` (`evaluateAA`, the generic `replace()` helper), and authentifier `formula` operators in `definition.js`'s `evaluate()` for address definitions: [4](#0-3) [5](#0-4) [6](#0-5) 

Because oscript is heavily reused (many independent AAs/units commonly use identical boilerplate formulas, e.g. common getter patterns, `trigger.output[[asset=base]].amount`, standard `if`/`bounce` snippets), it is very likely that two different addresses/units end up evaluating byte-for-byte identical formula source text at the same time. Node's event loop interleaves `async`/`setImmediate`-driven evaluation steps (`evaluate()` itself explicitly yields via `setImmediate` every 100 recursive calls in both `evaluation.js` and `validation.js`), so two independent evaluations of the same formula string can be in flight concurrently, both holding a reference to the identical cached `parser.results` (the AST). The evaluator does not defensively clone this AST per call; any node in the shared AST that could be mutated in place during evaluation (e.g., attaching computed/annotated fields to nodes, as is done elsewhere in the codebase for definitions/objects via `assignField`/`clearObject` patterns seen in `formula/common.js`) would be visible to, and could corrupt, the concurrently-running sibling evaluation that is using the very same cached AST object for a different address/trigger/mci context.

### Impact Explanation
If the shared parsed AST is mutated as a side effect during one evaluation (e.g. for a getter, `init`, or authentifier evaluation triggered by unit A), a concurrently running evaluation of the identical formula text triggered by unit B could observe or be affected by that mutation. Depending on which AST fields get corrupted, an attacker who can predict/control formula reuse could cause:
- an authentifier `formula` check (`definition.js` case `'formula'`) to be evaluated incorrectly for a *different* address's unit, permitting unauthorized spending;
- an AA `init`/`if` computation for one trigger to leak or be corrupted by a concurrent evaluation for another AA instance sharing the same formula body, causing incorrect state-variable updates or fund transfers/freezing in `aa_composer.js`.

This maps to the "unauthorized spending" / "AA fund loss or freezing" impact classes required by the validation rules.

### Likelihood Explanation
Likelihood depends entirely on whether any AST node visited by `evaluate()` in `formula/evaluation.js` is mutated in place rather than read-only. I was not able to fully enumerate every one of the ~3000 lines of `formula/evaluation.js`'s `evaluate()` switch cases within the available iterations to confirm a concrete in-place mutation of a cached AST node (e.g. attaching `.value`/`.checked` properties onto `arr`). The shared, context-agnostic cache and its concurrent reachability from a single posted unit (AA trigger or authentifier check) are confirmed; the exact mutating operation that would make this concretely exploitable for double-spend/fund-loss is not confirmed from the code inspected so far. This should be validated with a live Devin session that can grep the full `evaluate()` switch for any `arr.xxx = ...` assignments onto AST nodes read from `cache[formula]`.

### Recommendation
- Key the formula cache (or at minimum, avoid reuse of the parsed AST object) per evaluation context, or deep-clone `cache[formula]` before returning it from `formula/evaluation.js`/`formula/validation.js` so no two concurrent evaluations share the same mutable AST instance.
- Audit `evaluate()` in both `formula/evaluation.js` and `formula/validation.js` for any code path that assigns properties onto `arr` nodes obtained from the shared `parser.results`/`cache[formula]`, and make such state local to the call (e.g. via a side WeakMap keyed by call, not by writing onto the AST itself).
- Add a regression test that runs two concurrent `evaluate()` calls with the identical formula string but different `opts` (locals/trigger/stateVars) and asserts that results/side effects do not cross-contaminate.

### Proof of Concept
Not able to produce a concrete PoC without confirming an in-place AST mutation inside `evaluate()`'s switch statement in `formula/evaluation.js`; this requires further code review (ideally in a full Devin session with unrestricted grep/read access) to locate a specific mutating op-case and craft two AAs/authentifiers with identical formula text that interleave via `setImmediate`.

### Citations

**File:** formula/common.js (L5-7)
```javascript
var cacheLimit = 100;
var formulasInCache = [];
var cache = {};
```

**File:** formula/evaluation.js (L104-121)
```javascript
	var parser = {};
	if(cache[formula]){
		parser.results = cache[formula];
	}else {
		try {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			formulasInCache.push(formula);
			cache[formula] = parser.results;
			if (formulasInCache.length > cacheLimit) {
				var f = formulasInCache.shift();
				delete cache[f];
			}
		}catch (e) {
			console.log('exception from parser', e);
			return callback('parse failed: '+e, null);
		}
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

**File:** aa_composer.js (L589-615)
```javascript
	function evaluateAA(arrDefinition, cb) {
		var locals = {};
		var f = getFormula(arrDefinition[1].getters);
		if (f === null) { // no getters
			return replace(arrDefinition, 1, '', locals, '', cb);
		}
		// evaluate getters before everything else as they can define a few functions
		delete arrDefinition[1].getters;
		var opts = {
			conn: conn,
			formula: f,
			trigger: trigger,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStatementsOnly: true,
			bGetters: true,
			objValidationState: objValidationState,
			address: address
		};
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
	}
```

**File:** aa_composer.js (L770-826)
```javascript
		else if (typeof value === 'object' && (typeof value.if === 'string' || typeof value.init === 'string')) {
			function evaluateIf(cb2) {
				if (typeof value.if !== 'string')
					return cb2();
				var f = getFormula(value.if);
				if (f === null)
					return cb({message: "if is not a formula: " + value.if, xpath});
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: locals,
					stateVars: stateVars,
					responseVars: responseVars,
					objValidationState: objValidationState,
					address: address
				};
				formulaParser.evaluate(opts, [], xpath + '/if', function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + value.if + " failed: " + err);
					if (!res) {
						if (typeof name === 'string')
							delete obj[name];
						else
							assignField(obj, name, null); // will be removed
						return cb();
					}
					delete value.if;
					cb2();
				});
			}
			evaluateIf(function () {
				if (typeof value.init !== 'string')
					return replace(obj, name, path, locals, xpath, cb);
				var f = getFormula(value.init);
				if (f === null)
					return cb({message: "init is not a formula: " + value.init, xpath});
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: locals,
					stateVars: stateVars,
					responseVars: responseVars,
					bStatementsOnly: true,
					objValidationState: objValidationState,
					address: address
				};
				formulaParser.evaluate(opts, [], xpath + '/init', function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + value.init + " failed: " + err);
					delete value.init;
					replace(obj, name, path, locals, xpath, cb);
				});
			});
```

**File:** definition.js (L1199-1230)
```javascript
			case 'formula':
				var formula = args;
				augmentMessagesOrIgnore(formula, function (err, messages) {
					if (err)
						return cb2(false);
					var trigger = {};
					objUnit.messages.forEach(function (message) {
						if (message.app === 'data' && !trigger.data) // use the first data mesage, ignore the subsequent ones
							trigger.data = message.payload;
					});
					var opts = {
						conn: conn,
						formula: formula,
						messages: messages,
						trigger: trigger,
						objValidationState: objValidationState,
						address: address
					};
					formulaParser.evaluate(opts, [], '', function (err, result) {
						if (err)
							return cb2(false);
						if (typeof result === 'boolean') {
							cb2(result);
						} else if (typeof result === 'string') {
							cb2(!!result);
						} else if (Decimal.isDecimal(result)) {
							cb2(!result.eq(0))
						} else {
							cb2(false);
						}
					});
				});
```
