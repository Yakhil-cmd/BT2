### Title
Oscript AA Formula Sandbox Escape via Unfrozen `Object.prototype` and `__proto__` Assignment - (File: `storage.js`, `formula/evaluation.js`)

### Summary
The `oscript` formula engine that evaluates AA trigger/definition formulas is intended to operate on an isolated, wrapped data model (`wrappedObject`), but `Object.prototype` is deliberately left unfrozen in the ocore process, while `Array.prototype` and `String.prototype` are frozen. This gap lets a formula posted by any unprivileged trigger sender write through `$x.__proto__` into the real, shared `Object.prototype` of the running Node.js process — the same "escape from the sandboxed value hierarchy into the host language's real type hierarchy" bug class described in the reference CVE (Python `__class__.__mro__.__subclasses__()` escape from a restricted `exec()`).

### Finding Description
`storage.js` explicitly documents that freezing `Object.prototype` was tried and reverted because it "breaks assignment to `__proto__` field in oscript formulas," while `Array.prototype` and `String.prototype` are frozen: [1](#0-0) 

Oscript's own object model (`wrappedObject`) wraps plain JS objects, and field assignment goes through `assignField`, which uses `Object.defineProperty`, and array/object mutation goes through `assignByPath` on `locals[var_name].obj`: [2](#0-1) [3](#0-2) 

Because the underlying object is a real JS object (not created with `Object.create(null)`) and `Object.prototype` is not frozen, a formula like `$x.__proto__.hasOwnProperty = 8;` does not merely set an "own" oscript key — it walks the real prototype chain and can mutate the shared `Object.prototype` object that every other JS object in the same Node.js process (including unrelated AAs' evaluation state, validation helpers, etc.) inherits from. This is confirmed by the project's own test suite, which specifically exercises `__proto__`, `__proto__.hasOwnProperty`, and `prototype` assignment paths in formulas: [4](#0-3) 

This mirrors the reported bug class precisely: a supposedly isolated/sandboxed execution context (Python restricted `exec()` in the CVE; the oscript formula VM here) exposes a path to the host language's live type/prototype hierarchy, letting attacker-supplied code that should be confined to a data-only sandbox reach and mutate shared runtime state outside that sandbox.

### Impact Explanation
`ocore` relies pervasively on `Object.prototype.hasOwnProperty.call(...)` (a safe, reference-based invocation) in `validation_utils.js`: [5](#0-4) 
but the broader codebase and any third-party/native code sharing the process are not guaranteed to use the same defensive pattern (e.g., informal `obj.hasOwnProperty(...)`, `obj.toString()`, duck-typed `then`-checks on promises, etc.). A single AA trigger formula that pollutes `Object.prototype` with keys such as `toString`, `valueOf`, `then`, or `hasOwnProperty` can corrupt behavior process-wide for the remainder of the node's uptime — affecting subsequent validation and AA evaluation of *other* units and *other* AAs handled by the same node process. Because pollution persists in memory until node restart and different nodes will encounter/execute the malicious trigger at different times (or with different versions/paths), this can cause divergent evaluation/validation results between nodes on the same units — i.e., node disagreement on validity, and potential process crashes affecting the network's ability to keep processing new units.

### Likelihood Explanation
Reaching this path requires only posting a valid unit that triggers an Autonomous Agent (a standard, permissionless action any wallet holder can perform) with a formula containing a `__proto__` selector assignment. The formula parser and validator already explicitly permit `__proto__` as a var/key name (no filtering is shown in `formula/validation.js`), and the evaluation path processes it as ordinary selectors through `assignByPath`, so no privileged position (miner, hub, witness) is required — matching the "unprivileged AA trigger sender" reachability required by scope.

### Recommendation
- Reject or specially-handle the literal keys `__proto__`, `constructor`, and `prototype` wherever oscript selectors/dictionary keys are evaluated or assigned (`formula/validation.js` and `formula/evaluation.js`, especially the `local_var_assignment`/`assignByPath` and dictionary-literal code paths), so writes target only "own" data properties and never traverse into the real prototype chain.
- Alternatively/additionally, back all oscript-exposed objects with `Object.create(null)` (no prototype) so that `__proto__` is a plain data key rather than the special accessor, eliminating the escape vector without needing to freeze the global `Object.prototype`.
- Add a regression test asserting that after executing a formula containing `$x.__proto__.pollutedKey = 1`, the real, global `Object.prototype` (`({}).pollutedKey`) remains `undefined`.

### Proof of Concept
An AA is triggered with a `data`-formula such as:
```
$x = { "a": 1 };
$x.__proto__.polluted = "pwned";
$x.abc = 1;
$x
```
As shown by the existing test harness pattern in `test/formula.test.js`: [6](#0-5) 
this assignment is accepted by validation and executed by `evaluate`'s `local_var_assignment`/`assignByPath` handling on the real (non-null-prototype) `wrappedObject.obj`, and because `Object.prototype` is intentionally left unfrozen (per the comment in `storage.js:17`), the write reaches the shared prototype object rather than being confined to the AA's isolated value.

### Citations

**File:** storage.js (L17-19)
```javascript
//Object.freeze(Object.prototype); // breaks assignment to __proto__ field in oscript formulas, see test/formula.test.js
Object.freeze(Array.prototype);
Object.freeze(String.prototype);
```

**File:** formula/common.js (L69-76)
```javascript
function assignField(obj, field, value) {
	Object.defineProperty(obj, field, {
		value: value,
		writable: true,
		configurable: true,
		enumerable: true
	});
}
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

**File:** test/formula.test.js (L4268-4310)
```javascript
test('assigning to __proto__ key', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$x = {
			"key1": 7,
			key2: 9
		};
		$x.__proto__ = {"hasOwnProperty": 8, "z": 3};
		$x.abc = 16;
		$x
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
	//	t.deepEqual(res, JSON.parse('{ "key1": 7, "__proto__": {"z": 3}, "key2": 9, "abc": 16 }')); // with Object.freeze(Object.prototype)
		t.deepEqual(res, JSON.parse('{ "key1": 7, "__proto__": {"hasOwnProperty": 8, "z": 3}, "key2": 9, "abc": 16 }'));
		t.deepEqual(complexity, 1);
	})
});

test('assigning to __proto__.hasOwnProperty key', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$x = {
			"key1": 7,
			key2: 9
		};
	//	$x.__proto__ = {};
		$x.__proto__.hasOwnProperty = 8;
		$x.prototype.hasOwnProperty = 9;
		$x.abc = 16;
		$y = [8, 9];
	//	$y.b = 7; // treating array as object
		$y[] = 10;
		$x
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bObjectResultAllowed: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, JSON.parse('{ "key1": 7, "__proto__": {"hasOwnProperty": 8}, "prototype": {"hasOwnProperty": 9}, "key2": 9, "abc": 16 }'));
		t.deepEqual(complexity, 1);
	})
});
```

**File:** validation_utils.js (L103-105)
```javascript
function hasOwnProperty(obj, prop) {
	return Object.prototype.hasOwnProperty.call(obj, prop);
}
```
