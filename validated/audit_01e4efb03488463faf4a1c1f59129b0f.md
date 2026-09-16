### Title
Quadratic-complexity DoS via unbounded string concatenation inside `foreach`/`reduce` in oscript formulas - (File: formula/evaluation.js)

### Summary
The Suricata CVE-2026-31932 describes inefficient buffering that causes quadratic-time processing of attacker-supplied input. The analogous bug class in `ocore` is in the oscript formula evaluator: the `concat`/`||` operator rebuilds a new JS string on every invocation (`operand0.toString() + operand1.toString()`), and this operator can be driven from inside `foreach`/`map`/`reduce` loops whose iteration cost is accounted for by a fixed per-callback "complexity"/"op" budget rather than by the size of the string being repeatedly concatenated. This lets an AA author construct a formula that is cheap under the op-counting cost model but actually executes in O(n²) time/memory copying, because every iteration re-copies and re-allocates the whole accumulated string.

### Finding Description
`concat()` in `formula/evaluation.js` performs plain JS string concatenation and only checks the *final* length against `constants.MAX_AA_STRING_LENGTH`: [1](#0-0) 

This function backs both the binary `+`/`concat`/`||` formula operator and the `||=` state-var assignment operator, e.g.: [2](#0-1) 

The `foreach`/`map`/`reduce` opcode iterates over up to `count` elements, invoking the callback function once per element via `async.eachOfSeries`, and for `reduce` it threads an `accumulator` through every call: [3](#0-2) [4](#0-3) 

The cost accounting for this construct in `formula/validation.js` charges complexity/op-count proportional to the callback's own static complexity multiplied by iteration `count`, not to the size of any string value the callback happens to be concatenating: [5](#0-4) 

Because a single `||` (concat) call is charged the same fixed complexity regardless of operand length, an AA definer can write a getter/state-update formula equivalent to:
```
$s = '';
foreach(trigger.data.arr, N, ($x) => { $s = $s || $x; });
```
Each iteration's `$s || $x` copies the entire current `$s` (up to `MAX_AA_STRING_LENGTH`) to build the new string. Repeating this `N` times, with `$s` approaching the max length early and staying there, yields O(N · MAX_AA_STRING_LENGTH) byte-copying work for O(N) formula "ops" — i.e., quadratic real work relative to the nominal linear cost model, exactly mirroring the KRB5 buffering flaw where per-fragment processing cost was not properly bounded relative to buffer size.

### Impact Explanation
AA formula evaluation (including this quadratic-cost path) is executed by every full node validating an AA trigger unit and by light AAs' getters, meaning the disproportionate CPU/memory cost is paid network-wide, not just by the poster. If crafted formulas can be made to consume far more wall-clock time than their nominal complexity/op budget implies, an attacker (any address that can post an AA definition and trigger it) can degrade validation throughput for the whole network, potentially causing units carrying AA triggers to stall confirmation — matching the "network unable to confirm new units" impact criterion.

### Likelihood Explanation
Reachability requires only posting a normal AA definition (unprivileged AA author) and then sending a trigger unit (unprivileged AA trigger sender); no special privileges, hub/peer compromise, or protocol-level manipulation is needed — this is a straightforward, permissionless path directly through `aa_validation.js`/`aa_composer.js`/`formula/evaluation.js`. The concrete quadratic behavior, however, depends on exact constant values (`MAX_AA_STRING_LENGTH`, per-op complexity budgets, `MAX_OPS`/complexity ceiling) that bound how large `N` and the string can realistically get; I was not able to fully retrieve those numeric constants from `constants.js` in this session to compute the exact worst-case blow-up factor, so the severity should be validated against the live constants before treating this as confirmed-exploitable at scale.

### Recommendation
Charge `concat`/`||` (and `||=`) cost proportional to `operand0.length + operand1.length`, not a flat per-call complexity unit, and enforce a cumulative "total bytes concatenated" budget per formula evaluation (in addition to the existing final-length check), independent of the number of formula ops. Apply the same treatment to any other operator inside `foreach`/`map`/`reduce` whose real cost scales with operand size (e.g. `json_stringify`, `replace`, `split`/`join`) so that the op-count-based complexity metering in `formula/validation.js` cannot be gamed to hide O(n²) work behind an O(n) op count.

### Proof of Concept
1. Deploy an AA whose `init`/`getter`/state-update formula contains:
```
$s = '';
foreach(trigger.data.arr, 2000, ($x) => { $s = $s || $x; });
```
2. Trigger the AA with `trigger.data.arr` containing ~2000 elements, each a string sized so `$s` quickly approaches `MAX_AA_STRING_LENGTH` and remains near that size for the remaining iterations.
3. Measure evaluation wall-clock time versus a formula with the same op-count budget but no growing-string concatenation (e.g., 2000 no-op iterations) — the growing-concat version will show markedly higher (quadratic-scaling) evaluation time despite an identical nominal complexity score, demonstrating the accounting gap.

### Citations

**File:** formula/evaluation.js (L1367-1372)
```javascript
							if (assignment_op === '||=') {
								var ret = concat(value, res);
								if (ret.error)
									return setFatalError("state var assignment: " + ret.error, { arr }, false, cb);
								value = ret.result;
							}
```

**File:** formula/evaluation.js (L2346-2381)
```javascript
			case 'map':
			case 'filter':
			case 'reduce':
				var expr = arr[1];
				var count_expr = arr[2];
				var func_expr = arr[3];
				var initial_value_expr = arr[4];
				var bReduce = (op === 'reduce');
				evaluate(expr, function (res) {
					if (fatal_error)
						return cb(false);
					if (!(res instanceof wrappedObject))
						return setFatalError("scalar in foreach: " + res, { arr }, false, cb);
					evaluate(count_expr, function (count) {
						if (fatal_error)
							return cb(false);
						if (!Decimal.isDecimal(count))
							return setFatalError("count is not a number: " + count, { arr }, false, cb);
						count = count.toNumber();
						if (!ValidationUtils.isNonnegativeInteger(count))
							return setFatalError("count is not nonnegative integer: " + count, { arr }, false, cb);
						evaluateFunctionExpression(func_expr, arr, funcInfo => {
							if (fatal_error)
								return cb(false);
							var bArray = Array.isArray(res.obj);
							var arrElements = bArray ? res.obj : Object.keys(res.obj).sort();
							if (arrElements.length > count)
								return setFatalError("found " + arrElements.length + " elements in object, only up to " + count + " allowed", { arr }, false, cb);
							evaluate(bReduce ? initial_value_expr : "", initial_value => {
								if (fatal_error)
									return cb(false);
								var retValue = bArray ? [] : {};
								var accumulator = initial_value;
								async.eachOfSeries(
									arrElements,
									function (element, index, cb2) {
```

**File:** formula/evaluation.js (L2426-2449)
```javascript
										caller(r => {
											if (op === 'map') {
												r = toJsType(r);
												if (bArray)
													retValue.push(string_utils.cloneDeep(r));
												else
													assignField(retValue, element, string_utils.cloneDeep(r));
											}
											else if (op === 'filter') {
												r = toJsType(r);
												if (r) { // truthy
													if (bArray)
														retValue.push(string_utils.cloneDeep(element));
													else
														assignField(retValue, element, string_utils.cloneDeep(res.obj[element]));
												}
											}
											else if (bReduce) {
												accumulator = r;
												if (accumulator instanceof wrappedObject && isTooBigObj(bPostPemCurvesFix ? accumulator.obj : accumulator)) // now 1 level less deep
													return setFatalError("accumulator is too big", { arr }, undefined, cb2);
											}
											cb2(fatal_error);
										});
```

**File:** formula/evaluation.js (L2785-2794)
```javascript
		else { // one of operands is a string, then treat both as strings
			if (operand0 instanceof wrappedObject)
				operand0 = true;
			if (operand1 instanceof wrappedObject)
				operand1 = true;
			result = operand0.toString() + operand1.toString();
			if (result.length > constants.MAX_AA_STRING_LENGTH)
				return { error: "string too long after concat: " + result };
		}
		return { result };
```

**File:** formula/validation.js (L1018-1041)
```javascript
				readCount(count_expr, (err, count) => {
					if (err)
						return cb(err);
					readFuncProps(func_expr, (err, funcProps) => {
						if (err)
							return cb(err);
						if (funcProps.count_args !== null) {
							if (op !== 'reduce' && funcProps.count_args !== 1 && funcProps.count_args !== 2)
								return cb("callback function must have 1 or 2 arguments");
							if (op === 'reduce' && funcProps.count_args !== 2 && funcProps.count_args !== 3)
								return cb("callback function must have 2 or 3 arguments");
						}
						complexity += (funcProps.complexity === 0) ? 1 : count * funcProps.complexity;
						count_ops += count * funcProps.count_ops;
						if (op !== 'reduce')
							return evaluate(expr, cb);
						evaluate(expr, err => {
							if (err)
								return cb(err);
							evaluate(initial_value_expr, cb);
						})
					});
				});
				break;
```
