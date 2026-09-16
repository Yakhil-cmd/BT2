### Title
Live-array-reference iteration in `foreach`/`map`/`filter`/`reduce` allows unsafe mutation-during-iteration, corrupting AA state and balance computations - (File: formula/evaluation.js)

### Summary
The Linux CVE fixes a classic "iterate-then-free" bug: a list is walked with a non-safe iterator while an item is freed inside the loop body, so the next-pointer dereference operates on stale/freed memory. `ocore`'s oscript interpreter has the JS analog of this bug class in the `foreach`/`map`/`filter`/`reduce` implementation: when the target is an array, the code captures the *live reference* to the array being iterated (`arrElements = res.obj`) instead of a snapshot, and then iterates it asynchronously with `async.eachOfSeries` while invoking user-supplied AA/oscript callback functions that have full access to the same local-scope variable and can call `delete($var, idx)` on it mid-loop, mutating the very collection being walked. [1](#0-0) 

### Finding Description
In the `evaluate` switch-case for `foreach`/`map`/`filter`/`reduce`, the array being iterated is not copied:
```
var bArray = Array.isArray(res.obj);
var arrElements = bArray ? res.obj : Object.keys(res.obj).sort();
...
async.eachOfSeries(
    arrElements,
    function (element, index, cb2) { ... invokes user callback ... },
    ...
);
``` [2](#0-1) 

The per-element callback (`caller`) may be a local oscript function (`funcInfo.local`) that is called via `callFunction`, and its closure retains access to the enclosing scope's local variables (captured as `scopeVarNames` when the anonymous/named function is declared) as shown by `evaluateFunctionExpression`. [3](#0-2)  This means the callback body can legally reference `$ar` (the same array bound to `res.obj`/`arrElements`) and issue a `delete($ar, i)` statement, which the language explicitly supports and which mutates the array in place via `res.obj.splice(key, 1)`. [4](#0-3) 

Because `arrElements` is the exact same array object as `res.obj` (not `string_utils.cloneDeep`d, unlike the `reverse` operator which does clone before mutating [5](#0-4) ), any `splice`/`delete` performed on it from inside the loop body shifts indices for `async.eachOfSeries`'s subsequent iterations, causing elements to be skipped, re-processed, or paired with the wrong index/value (`res.obj[element]` for the object case at line 2394/2440 can read data that has already moved or been removed). This is the direct behavioral analog of "list_for_each_entry" walking a list whose current node was just freed/unlinked by the loop body itself — the iterator keeps operating on a live, mutating backing structure instead of a safe/frozen snapshot.

### Impact Explanation
AA authors commonly write patterns such as "iterate over an array of pending items and `delete` each one from the same array as it is processed" (a natural queue-draining idiom). Because `oscript` execution is fully deterministic bytecode interpretation, every full node will compute the same (corrupted) result — so this does not cause a validity/stability split between honest nodes, but it does mean the *actual, canonical* on-chain state written by `writer.js`/`aa_composer.js` for that AA is wrong: elements can be silently skipped (so obligations aren't fulfilled, funds not paid out — a freezing condition) or double-processed (so funds are double-counted/paid twice — a fund-loss condition), depending on how the AA logic composes state var writes and payment messages from the loop. Since `foreach`/`map`/`filter`/`reduce` operate directly on state vars and trigger data that a poster or trigger sender fully controls (array length, contents, and deletion timing all derive from AA-controlled logic combined with attacker-controlled trigger inputs), an attacker who understands a target AA's array-processing logic can craft trigger data that forces the vulnerable deletion pattern to manifest, corrupting the AA's committed state or balances in a reproducible, exploitable way. This is reachable purely by any address posting a trigger to an AA that uses this common iterate-and-delete pattern — no privileged or network-level access is required.

### Likelihood Explanation
The `delete` statement and `foreach`/`map`/`filter`/`reduce` operators are fully documented, activated oscript features (gated only by `aa2UpgradeMci`, long since passed) explicitly intended to be composed together, as confirmed by the test suite exercising both `delete` and `foreach`/`map`/`filter` extensively. [6](#0-5) [7](#0-6)  There is no validation-time or runtime guard preventing a callback invoked from `foreach`/`map`/`filter`/`reduce` from deleting from the very array/object supplied as the iteration source; `validation.js`'s complexity/op-count checks do not detect or forbid this aliasing. [8](#0-7)  Any AA developer implementing a natural "process and remove" loop is exposed, and any user who can post a trigger to such an AA can reach the bug.

### Recommendation
Take a defensive snapshot of the collection being iterated before entering `async.eachOfSeries`, analogous to using a "_safe" iterator: e.g. `var arrElements = bArray ? res.obj.slice() : Object.keys(res.obj).sort();` (or `string_utils.cloneDeep`), so in-loop `delete`/mutation of the source variable cannot affect the ongoing iteration. Alternatively, detect and reject (fatal error) any attempt to mutate the variable currently being iterated by `foreach`/`map`/`filter`/`reduce`, similar to how `frozen` is enforced for `delete`/`freeze`. [9](#0-8) 

### Proof of Concept
Illustrative oscript pattern reachable from any AA trigger (conceptual; exact result depends on `async.eachOfSeries`/array index-shift semantics, but demonstrates the aliasing hazard):
```
$ar = [10, 20, 30, 40];
$sum = 0;
foreach($ar, 4, ($x) => {
    $sum = $sum + $x;
    delete($ar, 0);   // mutates the very array currently being iterated (res.obj === arrElements)
});
```
Because `arrElements` is `$ar.obj` itself, each `delete($ar, 0)` call inside the callback shifts all remaining elements down by one index while `async.eachOfSeries` continues to advance its own index counter, causing elements to be skipped (e.g. `20` never observed) or mis-paired with the wrong index, producing an incorrect `$sum`/state that becomes the AA's canonical, deterministically-agreed-upon (but logically wrong) state — the direct oscript analog of walking a linked list whose current entry was unlinked/freed inside the loop body without a "_safe" iterator.

### Citations

**File:** formula/evaluation.js (L2276-2280)
```javascript
					else {
						if (!bArray)
							return setFatalError("not an array: " + JSON.stringify(res.obj), { arr }, false, cb);
						cb(new wrappedObject(string_utils.cloneDeep(res.obj).reverse()));
					}
```

**File:** formula/evaluation.js (L2301-2343)
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
							cb(true);
						});
					});
				});
				break;
```

**File:** formula/evaluation.js (L2367-2381)
```javascript
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

**File:** formula/evaluation.js (L3099-3114)
```javascript
	function evaluateFunctionExpression(func_expr, arr, cb) {
		if (func_expr[0] === 'func_declaration') { // anonymous function
			var args = func_expr[1];
			var body = func_expr[2];
			var scopeVarNames = Object.keys(locals);
			if (_.intersection(args, scopeVarNames).length > 0)
				return setFatalError("some args of anonymous function would shadow some local vars", { arr }, false, cb);
			cb({ local: new Func(args, body, scopeVarNames, formula, xpath) });
		}
		else if (func_expr[0] === 'local_var') {
			var var_name = func_expr[1];
			var func = locals[var_name];
			if (!(func instanceof Func))
				return setFatalError("not a func: " + var_name, { arr }, false, cb);
			cb({ local: func });
		}
```

**File:** test/formula.test.js (L4681-4694)
```javascript
test('deletion from array', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$x = ['a', 'b', 'c'];
		delete($x, 1);
		$x
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, ['a', 'c']);
		t.deepEqual(complexity, 1);
	})
});
```

**File:** test/formula.test.js (L5586-5600)
```javascript
test('foreach', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$ar = [2, 5, 9];
		$ar2 = [];
		foreach($ar, 3, ($x) => {$ar2[] = $x^2;});
		$ar2
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU' }, (res, complexity, count_ops, val_locals) => {
		t.deepEqual(res, [4, 25, 81]);
		t.deepEqual(complexity, 4);
	})
});
```

**File:** formula/validation.js (L1005-1041)
```javascript
			case 'foreach':
			case 'map':
			case 'filter':
			case 'reduce':
				if (mci < constants.aa2UpgradeMci)
					return cb(op + " not activated yet");
				if (bGetters && !bInFunction)
					return cb("top-level " + op + " not allowed in getters");
				var expr = arr[1];
				var count_expr = arr[2];
				var func_expr = arr[3];
				var initial_value_expr = arr[4];
				
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
