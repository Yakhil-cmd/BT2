## Analysis

The CVE describes unbounded recursive descent (no depth limit) in a parser/demangler causing stack exhaustion on attacker-controlled input. The closest reachable analog in `ocore` is the recursive `evaluate()` function inside `definition.js` that walks address/asset spending-condition trees (`validateDefinition`/`validateAuthentifiers`), which is invoked for every unit that defines or references an address definition or asset condition — i.e., reachable directly from an unprivileged unit poster.

Unlike the two other recursive tree-walkers in the codebase that were hardened against deep nesting — `aa_validation.js`'s `validate()`, which enforces an explicit `MAX_DEPTH` check plus periodic `setImmediate` stack interruption [1](#0-0) , and `formula/validation.js`'s `evaluate()`, which enforces `depth > 100` with `maximum depth exceeded` plus periodic stack interruption [2](#0-1)  — `definition.js`'s `evaluate()` used to validate address/asset definitions has **no explicit recursion-depth guard and no periodic call-stack interruption**. It only tracks a global `complexity`/`count_ops` counter against `MAX_COMPLEXITY`/`MAX_OPS` [3](#0-2) .

Several operators recurse purely synchronously into `evaluate()` again without ever yielding the event loop, most notably `not`, which unconditionally calls `evaluate(args, path, true, cb)` on its single child [4](#0-3) . The same absence of depth/stack protection exists in the sibling `validateAuthentifiers`'s inner `evaluate()`, which also recurses on `or`/`and`/`r of set`/`weighted and`/`not`-style structures using `async.eachSeries` with callbacks that fire synchronously [5](#0-4) .

Because `not` consumes only 1 unit of complexity/ops per level while producing 1 level of pure synchronous JS recursion, an attacker can build a chain `['not',['not',['not', ... ['sig',{...}]]]]` deep enough to stay under `MAX_COMPLEXITY`/`MAX_OPS` yet exceed V8's default call-stack limit, throwing an uncaught `RangeError: Maximum call stack size exceeded` synchronously inside the validation code path (not delivered as a normal `cb(err)` validation failure). This code path is reached by:
- posting a unit that defines a new address (`validateDefinition`, called from `wallet_defined_by_addresses.js`'s `validateAddressDefinition` and from core unit validation) [6](#0-5) ,
- any asset issuer setting an `issue_condition`/`transfer_condition` (`evaluateAssetCondition` → `validateAuthentifiers`) [7](#0-6) ,
- or any author spending from/cosigning such an address, which re-validates the definition on every use [8](#0-7) .

I was not able to confirm the exact numeric values of `constants.MAX_COMPLEXITY`/`constants.MAX_OPS` from the available index (grep found the definitions in `constants.js` but content wasn't returned in full), so I cannot certify with 100% confidence that the permitted node budget is large enough in practice to exceed the V8 stack limit before hitting `MAX_OPS`. This is the main residual uncertainty — a Devin session with full file access would be needed to read the actual constant values and empirically test the recursion depth achievable within the complexity budget.

### Title
Unbounded synchronous recursion in address/asset definition `evaluate()` allows stack-exhaustion crash on validation - (File: definition.js)

### Summary
`definition.js`'s `evaluate()` (used by `validateDefinition`/`validateAuthentifiers` for address definitions and asset issue/transfer conditions) recurses synchronously into itself for operators such as `not`, `and`, `or`, `r of set`, `weighted and` with no explicit recursion-depth cap and no periodic call-stack interruption (`setImmediate`/`setTimeout`), unlike the equivalent tree-walkers in `aa_validation.js` and `formula/validation.js` which both implement such protections.

### Finding Description
Any unpriviledged unit poster can craft an address definition (or asset issue/transfer condition) that is a long linear chain of `['not', [...]]` wrappers. Each level costs only 1 unit toward `complexity`/`count_ops` [9](#0-8)  but adds one full synchronous JS stack frame via `evaluate(args, path, true, cb)` [4](#0-3) . There is no `depth` parameter tracked or bounded in this function, and no `setImmediate`-based stack-unwinding as exists in the analogous `aa_validation.js` `validate()` [1](#0-0)  and `formula/validation.js` `evaluate()` [2](#0-1) . If the number of nesting levels permitted within `MAX_COMPLEXITY`/`MAX_OPS` exceeds V8's default call-stack limit, the process throws an uncaught `RangeError` synchronously from deep inside validation rather than returning a normal validation error via callback.

### Impact Explanation
A crash caused by stack exhaustion during unit/definition validation is a process-level Denial of Service: any node (full node, hub, or light wallet performing local address-definition validation) that attempts to validate the malicious unit/definition/asset-condition crashes. Because unit and asset-condition validation happens on every peer that receives or re-validates the referencing unit, this can propagate a crash across many nodes, potentially halting confirmation/propagation of otherwise-valid units — matching the "network unable to confirm new units" impact category.

### Likelihood Explanation
Reachability is straightforward for any unprivileged actor: defining a new address, an asset's `issue_condition`/`transfer_condition`, or spending from/cosigning an address triggers `validateDefinition`/`validateAuthentifiers`. The likelihood that the attack is actually exploitable depends on whether `MAX_COMPLEXITY`/`MAX_OPS` permit enough nesting depth to exceed the JS engine's stack limit — this numeric threshold could not be confirmed from the available index and requires direct inspection of `constants.js` and empirical testing.

### Recommendation
Add an explicit recursion-depth counter to `definition.js`'s `evaluate()` (both in `validateDefinition` and `validateAuthentifiers`), mirroring the `MAX_DEPTH` check in `aa_validation.js` and the `depth > 100` check in `formula/validation.js`, and periodically break the synchronous call chain with `setImmediate`/`setTimeout` as those two modules already do.

### Proof of Concept
Construct an address definition (or asset `issue_condition`) of the form:
```
["not", ["not", ["not", ... ["not", ["sig", {"pubkey": "<valid pubkey>"}]] ... ]]]
```
nested to a depth chosen to stay within `MAX_COMPLEXITY`/`MAX_OPS` (value to be confirmed in `constants.js`) but beyond V8's default synchronous call-stack limit (typically on the order of several thousand to ~15000 frames depending on frame size), then post it as a new address definition or as an asset's `issue_condition`/`transfer_condition`, and observe the validating node crash with `RangeError: Maximum call stack size exceeded` instead of a graceful validation error.

### Citations

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

**File:** definition.js (L103-118)
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
		switch(op){
```

**File:** definition.js (L397-399)
```javascript
			case 'not':
				evaluate(args, path, true, cb);
				break;
```

**File:** definition.js (L641-643)
```javascript
function evaluateAssetCondition(conn, asset, arrDefinition, objUnit, objValidationState, cb){
	validateAuthentifiers(conn, null, asset, arrDefinition, objUnit, objValidationState, null, cb);
}
```

**File:** definition.js (L646-691)
```javascript
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
	
	function evaluate(arr, path, cb2){
		var op = arr[0];
		var args = arr[1];
		switch(op){
			case 'or':
				// ['or', [list of options]]
				var res = false;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res || arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3("found") : cb3();
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
			case 'and':
				// ['and', [list of requirements]]
				var res = true;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res && arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
```

**File:** definition.js (L1449-1454)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
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
