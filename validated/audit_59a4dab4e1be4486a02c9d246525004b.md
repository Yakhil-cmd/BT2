## Title
Frozen-variable protection in oscript can be bypassed via a side-effecting function call embedded in the same assignment statement — (File: `formula/evaluation.js`)

### Summary
`Text::CSV_XS`'s bug stems from caching a state pointer (the Perl argument stack top) *before* invoking a user callback, then trusting that cached pointer *after* the callback returns, even though the callback can invalidate it. The oscript evaluator in `ocore` has the same class of defect: the `local_var_assignment` handler checks `locals[var_name].frozen` **before** evaluating the right-hand side expression, but the right-hand side can contain a function call whose side effects `freeze()` that very same variable. When the assignment resumes after the call returns, the frozen check is never re-verified, so the "immutable" object gets mutated anyway.

### Finding Description
In `formula/evaluation.js`, the `local_var_assignment` case performs the frozen check once, up front: [1](#0-0) 

It then evaluates `rhs` — an arbitrary oscript expression that may include a call to a local function (`func_call`): [2](#0-1) 

Local functions share their enclosing scope's variable *references* (not copies) via `scopeVarNames`, and `callFunction` copies those same object references into `func_locals` before executing the function body against the shared `locals` object: [3](#0-2) 

Inside that function body, `freeze` mutates the `wrappedObject` in place (`locals[var_name].frozen = true`), which is the *same* object reference the outer assignment is holding: [4](#0-3) 

When control returns to `local_var_assignment`'s rhs callback, the code re-checks only that the variable is still a `wrappedObject` — it does **not** re-check `.frozen` — before writing through `assignByPath`: [5](#0-4) 

This mirrors the CVE's root cause precisely: a validity/state check (`frozen` flag / stack pointer) is captured before a callback (`freeze()` / registered Perl callback) that can invalidate it, and the code proceeds to use the stale check result afterward. The existing test suite even documents that freezing works correctly when done in a *separate* statement before mutation (`freezing in a function`, test at `test/formula.test.js:5024`), confirming the check-then-use pattern is intentional and only fails when the freeze happens as a side effect nested inside the same assignment's rhs evaluation, a scenario not covered/guarded against.

### Impact Explanation
`freeze()` is oscript's explicit mechanism for AA authors to make a state/local object immutable, typically used to lock in validated terms, computed distribution tables, or escrow conditions so they cannot be altered by later code paths. If this guarantee can be silently defeated within a single assignment statement whenever the rhs triggers a local function that calls `freeze()` on the very variable being mutated, an AA that relies on this invariant to gate fund-affecting logic can have its "locked" state corrupted, deterministically leading to incorrect fund distribution or AA fund loss/miscalculation. Because the bug is fully deterministic (all nodes execute the same oscript engine and reach the identical, wrong result), it does not cause a validity/stability disagreement between nodes, but it does undermine a documented security primitive of the oscript language that AA authors depend on for financial logic correctness.

### Likelihood Explanation
Exploitation requires the affected AA's own formula code to contain the specific interleaving pattern — an assignment `$x.selector = f(...)` where `f` (a locally-declared function sharing `$x` via closure) calls `freeze($x)` as part of its evaluation. This is a plausible, if non-obvious, pattern for AA authors who structure validation/locking logic inside helper functions invoked from assignment expressions, and it can be reached by a trigger sender who supplies trigger data that routes execution through the vulnerable code path (e.g., a conditional `freeze()` call gated by trigger fields). It does not require any privileged access — an ordinary AA trigger sender can drive the code path once such an AA exists.

### Recommendation
Re-validate `locals[var_name].frozen` (and that `locals[var_name]` is still the expected object) immediately before the final `assignByPath` write in the `local_var_assignment` handler (`formula/evaluation.js:1268-1292`), rather than relying solely on the check performed prior to evaluating `rhs`. The same re-validation should be applied to the `delete` case (`formula/evaluation.js:2301-2343`), where selectors/keys are evaluated after the frozen check and could similarly trigger a `freeze()` side effect before the mutating `splice`/`delete` executes.

### Proof of Concept
```
$x = {a: 8};
$f = () => { freeze($x); 9 };
$x.b = $f();   // frozen check passes before $f() runs and freezes $x;
               // mutation still succeeds afterward, defeating freeze()
$x             // => {a: 8, b: 9} even though $x was frozen mid-statement
```
Compare with the existing passing test that freezes in a *separate* statement, where the subsequent mutation is correctly rejected: [6](#0-5)

### Citations

**File:** formula/evaluation.js (L1238-1245)
```javascript
					if (hasOwnProperty(locals, var_name)) {
						if (!selectors)
							return setFatalError("reassignment to " + var_name + ", old value " + locals[var_name], { arr }, false, cb);
						if (!(locals[var_name] instanceof wrappedObject))
							return setFatalError("variable " + var_name + " is not an object", { arr }, false, cb);
						if (locals[var_name].frozen)
							return setFatalError("variable " + var_name + " is frozen", { arr }, false, cb);
					}
```

**File:** formula/evaluation.js (L1261-1261)
```javascript
					evaluate(rhs, function (res) {
```

**File:** formula/evaluation.js (L1268-1292)
```javascript
						if (hasOwnProperty(locals, var_name)) { // mutating an object
							if (!selectors)
								return setFatalError("reassignment to " + var_name + " after evaluation", { arr }, false, cb);
							if (!(locals[var_name] instanceof wrappedObject))
								return setFatalError("variable " + var_name + " is not an object (again)", { arr }, false, cb);
							if (Decimal.isDecimal(res))
								res = res.toNumber();
							if (res instanceof wrappedObject) {
								if (isTooBigObj(res.obj))
									return setFatalError("resulting mutated object is too big", { arr }, false, cb);
								res = string_utils.cloneDeep(res.obj);
							}
							evaluateSelectorKeys(selectors, arr, function (arrKeys) {
								if (fatal_error)
									return cb(false);
								try {
									assignByPath(locals[var_name].obj, arrKeys, res);
									if (isTooBigObj(locals[var_name].obj))
										return setFatalError("mutated object is too big", { arr }, false, cb);
									cb(true);
								}
								catch (e) {
									setFatalError(e.toString(), { arr }, false, cb);
								}
							});
```

**File:** formula/evaluation.js (L2284-2298)
```javascript
			case 'freeze':
				var var_name_expr = arr[1];
				evaluate(var_name_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (!hasOwnProperty(locals, var_name))
						return setFatalError("no such variable: " + var_name, { arr }, false, cb);
					if (locals[var_name] instanceof Func)
						return setFatalError("functions cannot be frozen: " + var_name, { arr }, false, cb);
					if (locals[var_name] instanceof wrappedObject)
						locals[var_name].frozen = true;
					else
						console.log("skipping freeze of a scalar: " + var_name);
					cb(true);
				});
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

**File:** test/formula.test.js (L5024-5038)
```javascript
test('freezing in a function', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$x = {a:8};
		$f = ()=>{ freeze($x); };
		$f();
		$x.b = 9;
		$x
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
	})
});
```
