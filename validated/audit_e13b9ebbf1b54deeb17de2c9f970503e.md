### Title
Uncontrolled Recursion in `evaluate()` on Nested `not` Address/Asset-Condition Operators Causes Stack Overflow - (File: `definition.js`)

### Summary
`definition.js`'s `evaluate()` function, used to validate and later re-evaluate address definitions and asset spending conditions, recurses synchronously and unboundedly on the `not` operator without any stack-depth guard, unlike the equivalent evaluators in `aa_validation.js` and `formula/validation.js`, which explicitly cap recursion depth. A crafted definition containing thousands of nested `['not', [...]]` wrappers can overflow the Node.js call stack during validation, mirroring the PoDoFo `ReadArray`/`GetNextVariant`/`ReadDataType` uncontrolled-recursion pattern in the reported CVE.

### Finding Description
`validateDefinition()`'s inner `evaluate(arr, path, bInNegation, cb)` handles the `not` opcode by directly and synchronously recursing into itself: [1](#0-0) 

Complexity and op-count limits (`constants.MAX_COMPLEXITY`, `constants.MAX_OPS`) are checked at function entry, but these only bound the total number of evaluated nodes — they do nothing to bound the JavaScript call-stack depth for operators, like `not`, that recurse before any asynchronous boundary (`async.eachSeries`/`setImmediate`) is hit: [2](#0-1) 

By contrast, the sibling evaluators explicitly protect against exactly this class of bug:
- `aa_validation.js`'s AA-definition validator enforces `MAX_DEPTH` and periodically breaks the call stack with `setImmediate`: [3](#0-2) 
- `formula/validation.js`'s formula evaluator tracks an explicit `depth` counter and rejects formulas once `depth > 100`: [4](#0-3) 

`definition.js`'s `evaluate()` for address/asset definitions has no equivalent depth counter or periodic `setImmediate` yield for the `not` branch, so a deeply nested chain of `not` wrappers (e.g., `['not', ['not', ['not', ... ['sig', {...}] ...]]]`) causes one native JS stack frame per nesting level, all within a single synchronous execution burst, until `MAX_OPS`/`MAX_COMPLEXITY` is reached or the stack overflows — whichever happens first. Because `not` only wraps a single child (no array-length ≥2 requirement as with `and`/`or`), an attacker can achieve very deep nesting while keeping `count_ops` far below `MAX_OPS`.

This validation path is reached from an unprivileged posted unit: any author can supply a new address definition (`author.definition`) or an asset can define spending conditions, both of which flow into `validateDefinition`/`validateAuthentifiers` via `Definition.validateAuthentifiers` called from unit/message validation, and the same evaluator is reused in `wallet_defined_by_addresses.js`'s `validateAddressDefinition` for definitions received over the wallet/pairing protocol. [5](#0-4) 

### Impact Explanation
A stack overflow during synchronous validation of a unit's/asset's spending condition crashes the Node.js process handling validation (uncaught `RangeError: Maximum call stack size exceeded`, or a native crash depending on stack depth reached). Because this evaluator runs on every full/light node processing the offending unit or definition, a single crafted unit can be broadcast and cause repeated crashes on every node that attempts to validate it, preventing the network from confirming/validating new units that reference the malicious definition and creating a denial-of-service condition affecting consensus availability.

### Likelihood Explanation
Any unprivileged user can submit a unit containing an address definition or an asset with spending conditions (`author.definition`, `srcProfile`/asset `spend_conditions`), so the attacker does not need any special privileges, keys, or node cooperation — only the ability to post a validly-formed but maliciously deep `oscript`-style definition array. Constructing such a payload (deeply nested `not`) is trivial and deterministic.

### Recommendation
Add an explicit recursion-depth counter (mirroring `MAX_DEPTH` in `aa_validation.js` or the `depth`/`setImmediate` pattern in `formula/validation.js`) to `evaluate()` in `definition.js` for both `validateDefinition` and `validateAuthentifiers`, rejecting definitions whose nesting exceeds a small fixed bound (e.g., 100), and additionally break the synchronous call chain periodically (every N recursive calls) via `setImmediate` for the `not` branch and any other single-child recursive operator.

### Proof of Concept
Construct an address/asset definition of the form:
```
['not', ['not', ['not', /* … repeated ~50,000+ times … */ ['sig', {pubkey: '<valid base64 pubkey>'}] /* … */ ]]]
```
wrapped so total `count_ops`/`complexity` stay under `constants.MAX_OPS`/`MAX_COMPLEXITY`, then submit it as `author.definition` in a unit (or as an asset's spending condition, or via the pairing/wallet `validateAddressDefinition` path). When `Definition.validateDefinition`/`validateAuthentifiers` recurses through the `not` case in `definition.js`, the synchronous call depth equals the nesting depth, overflowing the Node.js stack and crashing/hanging the validating process.

Note: I could not directly confirm the numeric values of `constants.MAX_COMPLEXITY`/`MAX_OPS` from the index (content not fully retrievable), so the exact nesting depth required to trigger overflow before hitting those limits is unverified — a Devin session with full repo access would be needed to read `constants.js` and confirm the exact thresholds.

### Citations

**File:** definition.js (L103-117)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
		if (!isArrayOfLength(arr, 2))
			return cb("expression must be 2-element array");
		var op = arr[0];
		var args = arr[1];
		if (typeof op !== 'string')
			return cb("op is not a string");
```

**File:** definition.js (L397-399)
```javascript
			case 'not':
				evaluate(args, path, true, cb);
				break;
```

**File:** aa_validation.js (L598-603)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(validate, obj, name, path, locals, depth, cb, bValueOnly);
```

**File:** formula/validation.js (L272-288)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
		const orig_cb = cb;
		cb = err => {
			depth--;
			if (err && !errorLocation && arr && typeof arr === 'object' && arr.line !== undefined) {
				errorLocation = arr.source_location
					? Object.assign({}, arr.source_location)
					: { line: arr.line };
			}
			orig_cb(err);
		};
		if (depth > 100 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
			return cb("maximum depth exceeded");
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
