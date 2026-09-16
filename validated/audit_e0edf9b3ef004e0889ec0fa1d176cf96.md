### Title
Uncaught TypeError crash in AA formula JSON/array/dictionary size-limit check — ([File: formula/evaluation.js])

### Summary
The oscript/AA formula evaluator enforces object-size limits on `json_parse` results, array literals and dictionary literals by calling `string_utils.isTooBigObj(obj, opts)`, but every call site in `formula/evaluation.js` invokes it with only one argument. `isTooBigObj`'s second parameter is destructured with no `= {}` fallback, so calling it without the options object throws an unhandled `TypeError` instead of returning a boolean size check. This mirrors the CVE-2025-0695 pattern in Cesanta Frozen: a JSON-processing resource-limit mechanism that, when reachable with attacker-supplied input, crashes the component instead of gracefully rejecting oversized/complex data.

### Finding Description
`isTooBigObj` is declared as: [1](#0-0) 
requiring a second argument object to destructure `depthLimit`/`nodesLimit`/`lengthLimit`. Every call site found in the AA formula evaluator omits this second argument:

- `json_parse` result check: [2](#0-1) 
- Array literal intermediate/result checks: [3](#0-2) 
- Dictionary literal intermediate/result checks: [4](#0-3) 

Because the second parameter is `undefined` at each of these call sites and the function signature has no default for the whole parameter (`{...} `, not `{...} = {}`), the destructuring assignment throws `TypeError: Cannot destructure property 'depthLimit' of 'undefined' as it is undefined`. This throw happens synchronously inside the `evaluate()` callback chain of the AA formula interpreter, which has no surrounding `try/catch` at these points, so the exception propagates as an uncaught exception in whatever context is driving AA trigger/getter evaluation (e.g., `aa_composer.js`).

This is directly analogous to the Frozen CVE: a "resource limiting" code path meant to bound allocation/complexity for JSON-derived data instead throws when exercised, turning the safety check itself into the crash vector.

### Impact Explanation
`json_parse`, array literals (`[...]`) and dictionary literals (`{...}`) are extremely common oscript constructs used in AA definitions and are reachable by:
- Any unprivileged user sending a trigger unit to an AA whose script parses trigger `data` with `json_parse` and produces an object/array result, or that builds any array/dictionary literal that reaches the periodic size-check (`count - prevCount >= 100`) or completes evaluation (final check).
- AA getters and state formulas evaluated during unit/AA validation and trigger processing on every full node.

If the throw is truly unguarded up the stack, a single crafted trigger unit or formula invocation can crash node processes evaluating that AA (validators/witnesses/light-vendor nodes alike), which is a network-wide denial-of-service risk: nodes could crash while trying to validate/process a unit, potentially stalling stabilization and confirmation of new units — the same class of impact the rules require (network unable to confirm new units).

### Likelihood Explanation
`json_parse`, array literals `[...]`, and dictionary literals `{...}` are common, well-documented oscript features, so exercising these code paths does not require any privilege — merely posting an ordinary AA trigger to an already-deployed AA that uses them (or defining/using such an AA). Given the calls are missing a required argument unconditionally (not depending on any race or edge state), any code path that reaches an object/array result from these three operations will hit this bug on every invocation, making it easy to trigger repeatably.

### Recommendation
1. Give `isTooBigObj` a safe default so a missing options argument doesn't throw, e.g.: `function isTooBigObj(obj, { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 } = {})` in `string_utils.js`.
2. Fix all call sites in `formula/evaluation.js` (`json_parse`, array literal, dictionary literal checks) to pass the intended limit configuration explicitly rather than relying on the function's internal defaults.
3. Add regression tests that exercise `json_parse` on strings that parse to non-trivial objects/arrays, and array/dictionary literals of realistic size, verifying no uncaught exception is thrown and oversized inputs are rejected via the intended fatal-error path (`setFatalError`) instead of a JS exception.
4. Audit other call sites of `isTooBigObj` (e.g., in `aa_composer.js`) for the same missing-argument pattern.

### Proof of Concept
Deploy an AA whose bound formula does either:
```
$x = json_parse('{"a":1}');
```
or
```
$x = {a: 1};
```
and trigger it. Per the code at `formula/evaluation.js:1941` (for `json_parse`) or `formula/evaluation.js:1162`/`1202` (for dictionary/array literals), the AA evaluator calls `isTooBigObj(json)` / `isTooBigObj(obj)` with only one argument. Given `isTooBigObj`'s signature at `string_utils.js:286` has no default for its second parameter, this throws a `TypeError` during evaluation instead of returning a boolean, propagating as an uncaught exception in the AA formula evaluation flow triggered by the posted unit.

Note: I was unable to execute the test suite or trace every downstream caller (e.g., all invocation points of AA evaluation in `aa_composer.js`) to confirm whether an outer `try/catch` ultimately absorbs this exception before it reaches process level in every deployment path; this should be verified by running the existing `test/formula.test.js` `json_parse`/array/dictionary tests and confirming whether they currently pass, and by tracing exception handling in `aa_composer.js` around calls into `formula/evaluation.js`.

### Citations

**File:** string_utils.js (L286-286)
```javascript
function isTooBigObj(obj, { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 }) {
```

**File:** formula/evaluation.js (L1153-1163)
```javascript
								if (isTooBigObj(arrItems))
									return setFatalError("intermediate array is too big", { arr }, undefined, cb2);
							}
							cb2();
						})
					},
					function (err) {
						if (fatal_error)
							return cb(false);
						if (isTooBigObj(arrItems))
							return setFatalError("resulting array is too big", { arr }, false, cb);
```

**File:** formula/evaluation.js (L1193-1203)
```javascript
								if (isTooBigObj(obj))
									return setFatalError("intermediate dictionary is too big", { arr }, undefined, cb2);
							}
							cb2();
						});	
					},
					function (err) {
						if (fatal_error)
							return cb(false);
						if (isTooBigObj(obj))
							return setFatalError("resulting dictionary is too big", { arr }, false, cb);
```

**File:** formula/evaluation.js (L1941-1942)
```javascript
					if (typeof json === 'object' && isTooBigObj(json))
						return setFatalError("json_parse result is too big", { arr }, false, cb);
```
