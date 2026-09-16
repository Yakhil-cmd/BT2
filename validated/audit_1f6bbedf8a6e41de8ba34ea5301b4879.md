Confirmed: `callFunction` in `formula/evaluation.js:3050-3097` copies the enclosing scope's variables by reference into `func_locals` — `func.scopeVarNames.forEach(name => assignField(func_locals, name, locals[name]))` — and the callee gets the exact same `wrappedObject` instance (not a clone) for any array/object the closure captured. This confirms that a nested function invoked from inside `foreach`/`map`/`filter`/`reduce` can hold and mutate the very same `wrappedObject.obj` that is simultaneously being walked as `arrElements` in the caller's `async.eachOfSeries` loop (`formula/evaluation.js:2367-2450`).

### Title
Live-array mutation during `foreach`/`map`/`filter`/`reduce` iteration causes stale-index corruption in AA evaluation - (File: formula/evaluation.js)

### Summary
`formula/evaluation.js`'s `foreach`/`map`/`filter`/`reduce` implementation iterates over `arrElements`, which is a direct reference to the live array (`res.obj`) rather than a defensive copy, while invoking a user-supplied callback function once per element via `async.eachOfSeries`. Because `callFunction` passes closure variables by reference [1](#0-0) , an AA author can write a callback that calls the `delete` statement on the very same variable being iterated, mutating the shared array (via `res.obj.splice(...)`) mid-iteration [2](#0-1) . This is the same bug class as the Vim CVE: a structure that is being walked is freed/mutated by a nested callback triggered during that walk, leaving the outer iterator referencing stale indices/elements.

### Finding Description
In the `foreach`/`map`/`filter`/`reduce` case, `res` is the `wrappedObject` for the target variable and `arrElements` is assigned directly to `res.obj` when it's an array (no `cloneDeep`) [3](#0-2) . The elements are then processed one at a time by `async.eachOfSeries`, calling either a local function via `callFunction` or a remote getter via `callGetter` for each index [4](#0-3) .

`callFunction` builds the callee's scope by copying references from the outer `locals` for every name in `func.scopeVarNames` [5](#0-4) , so if the array variable (e.g. `$ar`) is in scope of the callback, the callback receives the identical `wrappedObject` instance, not a copy. Inside that callback the author can execute the `delete` statement, which — for arrays — performs `res.obj.splice(key, 1)` directly on the underlying array [6](#0-5) .

Because `arrElements` in the outer loop is the *same* array object, splicing it during the loop shifts subsequent indices. `async.eachOfSeries` continues iterating by the original index sequence against the now-mutated array, so elements are skipped, re-processed, or `undefined` values are fed into the callback (via `toOscriptType(element)`), corrupting the semantics of `map`/`filter`/`reduce` results (e.g., `retValue`/`accumulator`) without raising any error.

### Impact Explanation
`foreach`/`map`/`filter`/`reduce` are commonly used by AAs to iterate over trigger data, arrays of addresses/amounts, or accumulate balances (e.g., `reduce` building a payment total). If an attacker crafts an AA whose callback deletes elements from the array it is iterating (a pattern the language permits, since `delete` and `foreach` share the same locals by reference), the resulting `accumulator`/`retValue` diverges from the mathematically correct value with no fatal error raised. Because AA state-variable updates and payment outputs are derived directly from these results (see `updatedStateVars`/`arrResponses` computation in `aa_composer.js`, e.g. `handlePrimaryAATrigger` at `aa_composer.js:91-150`), a miscomputed `reduce`/`map` result can produce incorrect balances or payment amounts — enabling fund loss or an inconsistent AA state that diverges between nodes performing the same deterministic evaluation only if the divergence itself is non-deterministic; here it's deterministic misbehavior but exploitable to under/over-pay outputs relative to the AA author's intent, i.e., an AA fund-loss/logic-corruption bug.

### Likelihood Explanation
Reachable purely through oscript authored by any AA definer/poster — no privileged access is required. The pattern (declare an array local, declare a callback closing over it, call `delete` inside the callback, then call `foreach`/`map`/`filter`/`reduce` on the same array) is expressible in ordinary oscript syntax already exercised by existing tests (`test/formula.test.js:5802-5866`, `test/aa_composer.test.js` map/reduce tests), so no unusual permissions or bytecode injection is needed — just a specific oscript pattern.

### Recommendation
In the `foreach`/`map`/`filter`/`reduce` handler in `formula/evaluation.js` (~line 2371), take a shallow copy of `res.obj` (or freeze/snapshot the elements array) before starting `async.eachOfSeries`, e.g. `var arrElements = bArray ? res.obj.slice() : Object.keys(res.obj).sort();`, so that any in-place mutation performed by nested callback functions (via `delete`, or future ops) cannot affect the array/keys being iterated. Alternatively, mark `res` as implicitly frozen for the duration of the iteration and reject `delete` attempts on a variable that is currently being iterated.

### Proof of Concept
```
$ar = [1, 2, 3, 4, 5];
$f = ($x) => {
    delete($ar, [], 0);   // mutates $ar (same wrappedObject) while foreach/reduce is iterating it
    $x
};
$sum = reduce($ar, 5, ($acc, $x) => $acc + $f($x), 0);
```
Tracing through `formula/evaluation.js:2371` (`arrElements = res.obj`) and `formula/evaluation.js:2335` (`res.obj.splice(key, 1)`), each invocation of `$f` shrinks `$ar` in place while `async.eachOfSeries` continues to walk the original index sequence, causing elements to be skipped/reprocessed and `$sum` to differ from the value obtained without the `delete` call — demonstrating that the iteration state (`arrElements`) is stale relative to the live, concurrently-mutated array.

### Citations

**File:** formula/evaluation.js (L2301-2338)
```javascript
			case 'delete':
				var var_name_expr = arr[1];
				var selectors = arr[2];
				var key_expr = arr[3];
				evaluate(var_name_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (!hasOwnProperty(locals, var_name))
						return setFatalError("no such variable: " + var_name, { arr }, false, cb);
					if (!(locals[var_name] instanceof wrappedObject))
						return setFatalError("trying to delete a key from a non-object", { arr }, false, cb);
					if (locals[var_name].frozen)
						return setFatalError("variable " + var_name + " is frozen", { arr }, false, cb);
					selectSubobject(locals[var_name], selectors, arr, function (res) {
						if (fatal_error)
							return cb(false);
						if (!(res instanceof wrappedObject))
							return setFatalError("trying to delete a key from a subobject which is not an object", { arr }, false, cb);
						evaluate(key_expr, function (key) {
							if (fatal_error)
								return cb(false);
							if (!isValidValue(key) || typeof key === 'boolean')
								return setFatalError("bad key to delete: " + key, { arr }, false, cb);
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
```

**File:** formula/evaluation.js (L2370-2371)
```javascript
							var bArray = Array.isArray(res.obj);
							var arrElements = bArray ? res.obj : Object.keys(res.obj).sort();
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

**File:** formula/evaluation.js (L3065-3081)
```javascript
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
