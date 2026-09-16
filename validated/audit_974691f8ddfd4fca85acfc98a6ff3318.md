### Title
Live-array aliasing in `foreach`/`map`/`filter`/`reduce` allows an AA's own callback to mutate the collection while it is being enumerated - ([File: formula/evaluation.js])

### Summary
CVE-2016-9905 is a Firefox use-after-free/crash caused by mutating a document's sub-document list (add/remove) while it is being enumerated by `EnumerateSubDocuments`. The analogous bug class in `ocore` is enumerating a live, non-cloned array/object while the oscript callback invoked per-element is allowed to mutate that very same array (via `delete()`, `$arr[]=`, or index assignment) because of by-reference variable capture in `callFunction`.

### Finding Description
In `formula/evaluation.js`, the `foreach`/`map`/`filter`/`reduce` handler evaluates the target expression into a `wrappedObject` and then aliases the live array directly instead of taking a defensive copy: [1](#0-0) 

`arrElements = res.obj` is the actual mutable array object, not a clone. It is iterated with `async.eachOfSeries`, invoking a user-declared oscript function/closure for every element: [2](#0-1) 

Local variables (including objects) are captured into functions by reference, not by deep copy - confirmed by the project's own test showing an object mutated inside a called function is visible to the caller afterward: [3](#0-2) 

Because `func.scopeVarNames` closures reuse the same `locals[name]` object references (`callFunction`: `assignField(func_locals, name, locals[name])`), a callback function passed to `foreach`/`map`/`filter`/`reduce` can reach back into the enclosing scope and call `delete($arr, i)` or `$arr[]=x` on the very same array object currently being iterated: [4](#0-3) 

The `delete` opcode directly performs `res.obj.splice(key, 1)` on the wrapped object, which is the same JS array reference used by `arrElements` in the enclosing `foreach` call: [5](#0-4) 

Since `arrElements` is not a snapshot but a live reference, calling `delete()`/push mutation on it from inside its own iteration callback shifts indices mid-iteration: `async.eachOfSeries` visits an index-based position, but the underlying content at that index has changed (elements shifted left after a splice), so subsequent iterations silently operate on the wrong element (skip-one / duplicate-one semantics), or - if the array shrinks below the previously computed `count`/length - `res.obj[element]`/`element` accesses can read `undefined`, which is fed into `toOscriptType`, `assignField`, `string_utils.cloneDeep`, etc. without validation for "value became undefined mid-loop".

This is functionally the "enumerate sub-elements while adding/removing sub-elements" bug class from the CVE: the enumeration loop and the mutation of the same underlying collection are not isolated from each other.

### Impact Explanation
Because AA (Autonomous Agent) execution must be byte-for-byte deterministic across all full nodes for consensus to hold, any code path whose outcome depends on subtle JS engine mutation-during-iteration semantics, or that can produce an unexpected `undefined`/type error deep inside oscript evaluation, is dangerous:
- If the mutation-during-iteration produces a runtime state that is not defended by `setFatalError` (e.g., an uncaught exception thrown from deep in `cloneDeep`/`assignField`/`splice` handling of an out-of-range/undefined value), the AA trigger processing (`aa_composer.js`/`handleTrigger`) could crash or throw unexpectedly rather than gracefully bouncing the trigger, an "AA fund loss/freezing" scenario if state variables are left partially updated, or if it aborts unit processing that the network otherwise relies on to keep confirming units.
- Even absent an outright crash, an AA author who intentionally builds a "self-modifying array" foreach/map/filter/reduce can manufacture skip/duplicate semantics that let a poorly-written but otherwise correct-looking AA template silently misbehave (e.g., an accounting loop over pending payouts that skips or double-counts an entry due to the splice-during-iteration behavior), leading to unintended fund transfers from the AA's own balance.

### Likelihood Explanation
Reachable by any unprivileged AA author writing an oscript formula that is posted/activated once (definitions are validated once via `aa_validation.js`/`formula/validation.js`, but validation does not track whether a callback closure captures and mutates its own enclosing `foreach` target array — it only checks formula shape/complexity, not aliasing semantics). Any address can post a unit that triggers this AA. No privileged network position, hub, or peer role is required — this is purely a self-contained oscript evaluation issue triggerable by an ordinary AA trigger sender or the AA author's own contract logic.

### Recommendation
- In the `foreach`/`map`/`filter`/`reduce` handler, take a defensive shallow copy of `arrElements` (e.g., `arrElements = bArray ? res.obj.slice() : Object.keys(res.obj).sort()`) so the iterated index/element list is fixed for the duration of the loop, independent of later mutation of `res.obj` by the callback.
- Alternatively/also, detect and reject (fatal error) any attempt inside a `foreach`/`map`/`filter`/`reduce` callback to `delete`/mutate the same object instance that is the active iteration target (freeze it for the duration of the call, similar to the existing `frozen` flag mechanism already used elsewhere in `evaluation.js`).
- Add regression tests mirroring `test/formula.test.js`'s existing `delete()`/`foreach` tests but where the callback function itself deletes/pushes into the array being iterated, asserting deterministic, well-defined results (or a clean fatal error) rather than relying on incidental JS array/splice/index semantics.

### Proof of Concept
```
$arr = ['a','b','c'];
$f = () => { delete($arr, 0); }; // mutates the same array captured by closure
foreach($arr, 3, $f);
$arr
```
Tracing through `formula/evaluation.js`:
1. `expr` evaluates `$arr` to `res` (`wrappedObject` wrapping `['a','b','c']`).
2. `arrElements = res.obj` — same live array reference (not cloned) at `formula/evaluation.js:2371`.
3. `async.eachOfSeries(arrElements, ...)` begins iterating index 0 → element `'a'`, invoking `$f` via `callFunction`.
4. `$f`'s closure holds `$arr` by reference (scope capture, `formula/evaluation.js:3067-3069`), so `delete($arr, 0)` executes `res.obj.splice(0, 1)` on the exact array being enumerated (`formula/evaluation.js:2335`), shrinking it to `['b','c']`.
5. On the next iteration, `eachOfSeries` proceeds to index 1 of the now-mutated array (which used to be index 2, `'c'`), silently skipping `'b'` — demonstrating the enumerate-while-mutate skip/duplicate hazard analogous to CVE-2016-9905's `EnumerateSubDocuments` corruption while adding/removing sub-documents.

### Citations

**File:** formula/evaluation.js (L2324-2339)
```javascript
							if (Array.isArray(res.obj)) {
								if (Decimal.isDecimal(key))
									key = key.toNumber();
								else { // string
									var f = string_utils.toNumber(key);
									if (f === null)
										return setFatalError("key to be deleted is not a number: " + key, { arr }, false, cb);
									key = f;
								}
								if (!ValidationUtils.isNonnegativeInteger(key))
									return setFatalError("key to be deleted must be nonnegative integer: " + key, { arr }, false, cb);
								res.obj.splice(key, 1); // does nothing if the key is out of range
							}
							else
								delete res.obj[key.toString()]; // does nothing if the key doesn't exist
							cb(true);
```

**File:** formula/evaluation.js (L2354-2373)
```javascript
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
```

**File:** formula/evaluation.js (L2379-2426)
```javascript
								async.eachOfSeries(
									arrElements,
									function (element, index, cb2) {
										function getArgs(count_args) {
											var args = [];
											if (bReduce) {
												args.push(accumulator);
												count_args--; // remaining args
											}
											if (bArray) {
												var key = new Decimal(index);
												var value = toOscriptType(element);
											}
											else {
												var key = element;
												var value = toOscriptType(res.obj[element]);
											}
											if (value instanceof wrappedObject && res.frozen)
												value.frozen = true;
											if (count_args === 1)
												args.push(value);
											else
												args.push(key, value);
											return args;
										}
										var caller;
										if (funcInfo.local) {
											var func = funcInfo.local;
											var args = getArgs(func.args.length);
											caller = function (res_cb) {
												callFunction(func, args, undefined, { aa: address, call_line: arr.line, call_xpath: xpath }, res_cb);
											};
										}
										else if (funcInfo.remote) {
											var fargs = (func) => getArgs(func.args.length);
											caller = function (res_cb) {
												callGetter(conn, funcInfo.remote.remote_aa, funcInfo.remote.func_name, fargs, stateVars, objValidationState, astTrace, xpath, { caller_aa: address, call_line: arr.line, call_xpath: xpath }, (err, r) => {
													if (err)
														return setFatalError(err, { arr }, false, res_cb);

													astTrace.push({system: 'exit from getters', aa: funcInfo.remote.remote_aa, caller_aa: address, call_line: arr.line, call_xpath: xpath});
													res_cb(r);
												});
											};
										}
										else
											throw Error("neither local nor remote: " + funcInfo);
										caller(r => {
```

**File:** formula/evaluation.js (L3050-3081)
```javascript
	function callFunction(func, args, func_name, callInfo, cb) {
		const frameAA = callInfo && callInfo.aa ? callInfo.aa : address;
		const call_line = callInfo ? callInfo.call_line : undefined;
		const call_xpath = callInfo ? callInfo.call_xpath : undefined;
		astTrace.push({
			system: 'enter to func',
			formula: func.formula || formula,
			name: func_name,
			xpath: func.xpath || '',
			aa: frameAA,
			call_line,
			call_xpath,
		});
		if (early_return !== undefined)
			throw Error("function called after a return");
		var func_locals = {};
		// set a subset of locals that were present in the declaration scope
		func.scopeVarNames.forEach(name => {
			assignField(func_locals, name, locals[name]);
		});
		// set the arguments as locals too
		for (var i = 0; i < func.args.length; i++){
			var arg_name = func.args[i];
			var value = args[i];
			if (value === undefined) // no argument passed
				value = false;
			if (hasOwnProperty(func_locals, arg_name))
				return setFatalError("argument " + arg_name + " would shadow a local var", { arr: [] }, false, cb);
			assignField(func_locals, arg_name, toOscriptType(value));
		}
		var saved_locals = _.clone(locals);
		assignObject(locals, func_locals);
```

**File:** test/formula.test.js (L4581-4598)
```javascript
test('object mutated by function', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$f = ($o) => {
			$o.b = 'bb';
			$o.a = $o.a + 2;
		};
		$x = {a:5};
		$f($x);
		$x
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, { a: 7, b: 'bb' });
		t.deepEqual(complexity, 1);
	})
});
```
