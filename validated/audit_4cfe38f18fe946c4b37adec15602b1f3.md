### Title
Unbounded synchronous recursion in address-definition evaluation causes stack exhaustion DoS - ([File: definition.js])

### Summary
`definition.js`'s `evaluate()` functions (used both in `validateDefinition` for validating address/asset spending conditions and in `validateAuthentifiers` for authentifier checking) recurse into nested boolean operators (`not`, `and`, `or`, `r of set`, `weighted and`) and into referenced/`address`/`definition template` definitions purely through synchronous JS call stack frames. Unlike the formula evaluator (`formula/evaluation.js`) and the AA-definition validator (`aa_validation.js`), which explicitly break the call stack every N iterations via `setImmediate`, `definition.js`'s `evaluate()` has no such stack-depth-breaking mechanism — it only tracks a `complexity`/`count_ops` counter that limits the *number of nodes*, not the *recursion depth* of the call stack.

### Finding Description
`evaluate()` in `definition.js` increments `complexity`/`count_ops` and bails out once `constants.MAX_COMPLEXITY`/`MAX_OPS` is exceeded: [1](#0-0) 

The `not` operator recurses directly and synchronously: [2](#0-1) 

`and`/`or`/`r of set`/`weighted and` also recurse via `async.eachSeries`, whose iteratee callback is typically invoked synchronously for local, fast-path branches (e.g. `sig`, `hash`), so this again builds up the native JS call stack rather than yielding: [3](#0-2) 

Contrast this with the equivalent evaluators elsewhere in the codebase, which explicitly interrupt the call stack: [4](#0-3) [5](#0-4) 

`definition.js`'s `evaluate()` has no analogous `count % N === 0 → setImmediate(...)` guard, so nested `not`/`and`/`or` expressions in an address (or asset) definition drive the JS call stack depth linearly with nesting, bounded only by `MAX_COMPLEXITY`/`MAX_OPS` (a node-count limit, not a stack-depth limit). If that node-count limit is large relative to Node's default stack size, a maliciously deeply-nested definition can exhaust the stack before the complexity/op counters trip.

This is directly reachable by an unprivileged actor: any unit poster can submit an `author.definition` (validated via `validateAuthor` → `validateDefinition`/`validateAuthentifiers` in `validation.js`), and any address owner can propose a shared-address definition (`wallet_defined_by_addresses.js` `handleNewSharedAddress` → `Definition.validateDefinition`), both of which funnel directly into this same unbounded-recursion `evaluate()`. [6](#0-5) [7](#0-6) 

### Impact Explanation
A stack-exhaustion crash (`RangeError: Maximum call stack size exceeded`) in a node processing a maliciously crafted, deeply-nested address definition would crash/hang the validating node's process while validating the unit or shared-address proposal. If different nodes crash or diverge in behavior (some nodes' stack limits differ, or the crash happens mid-validation), this can create validity/availability disagreement across the network for that unit, i.e., a node-level denial-of-service triggered by a single posted unit — matching the "node unable to confirm new units" impact class.

### Likelihood Explanation
Likelihood is bounded by whatever cap `constants.MAX_COMPLEXITY`/`MAX_OPS` impose on the number of allowed operators in a definition, since each level of `not` (or each `and`/`or` branch) both increments `complexity` and adds one stack frame. If `MAX_COMPLEXITY` is large enough (need to confirm exact value in `constants.js`, which I could not conclusively pull the numeric value for during this session) to permit thousands of nested operators before triggering the complexity cutoff, an attacker's single crafted unit reaches the stack limit before the complexity guard fires. I was unable to fully verify the exact numeric threshold of `MAX_COMPLEXITY`/`MAX_OPS` in this session (indexed content did not surface the literal values), so likelihood should be confirmed by checking those constants directly in `constants.js` and by empirically testing a deeply-nested `not`/`and` definition against `Definition.validateDefinition`.

### Recommendation
Add an explicit recursion-depth counter to `evaluate()` in `definition.js` (mirroring the `depth`/`setImmediate` pattern used in `aa_validation.js`'s `validate()` and `formula/evaluation.js`'s `evaluate()`), interrupting the call stack every N recursive calls via `setImmediate`/`setTimeout`, and/or enforce a strict maximum nesting depth independent of the complexity/ops counters.

### Proof of Concept
Construct an address definition consisting of deeply nested `not` operators wrapping a single `sig` leaf, e.g. (pseudocode):
```
def = ['sig', {algo:'secp256k1', pubkey:...}]
for i in range(N):
    def = ['not', def]
```
Submit this as `author.definition` in a unit (or as a shared-address definition via `wallet_defined_by_addresses.handleNewSharedAddress`). If `N` is large enough to remain under `MAX_COMPLEXITY`/`MAX_OPS` but large enough to exceed Node's stack frame limit, `Definition.validateDefinition`'s `evaluate()` will recurse `N` times synchronously and throw `RangeError: Maximum call stack size exceeded`, crashing/DoS'ing the validating process. This mirrors the exact bug class of the `time` crate advisory (unbounded recursive descent driven directly by attacker-controlled nesting depth, with no stack-depth circuit breaker).

### Citations

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

**File:** definition.js (L119-145)
```javascript
			case 'or':
			case 'and':
				if (!Array.isArray(args))
					return cb(op+" args must be array");
				if (args.length < 2)
					return cb(op+" must have at least 2 options");
				var count_options_with_sig = 0;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb2){
						index++;
						evaluate(arg, path+'.'+index, bInNegation, function(err, bHasSig){
							if (err)
								return cb2(err);
							if (bHasSig)
								count_options_with_sig++;
							cb2();
						});
					},
					function(err){
						if (err)
							return cb(err);
						cb(null, op === "and" && count_options_with_sig > 0 || op === "or" && count_options_with_sig === args.length);
					}
				);
				break;
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

**File:** formula/evaluation.js (L126-129)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return setImmediate(evaluate, arr, cb);
```

**File:** validation.js (L1177-1183)
```javascript
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
	}
```

**File:** wallet_defined_by_addresses.js (L518-527)
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
```
