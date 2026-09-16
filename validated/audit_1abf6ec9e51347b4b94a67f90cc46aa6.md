## Title
Unbounded synchronous recursion in address-definition evaluation causes stack-overflow crash - (File: `definition.js`)

### Summary
`definition.js`'s two `evaluate()` closures (inside `validateDefinition()` and inside `validateAuthentifiers()`) recurse into nested `['address', ...]` definitions with no per-call-stack circuit breaker. Other oscript/AA evaluators in the same codebase (`aa_validation.js`, `formula/validation.js`, `formula/evaluation.js`) explicitly protect against deep native call stacks by interrupting every 100 iterations with `setImmediate`/`setTimeout` (see e.g. `formula/validation.js` `evaluate()` at [1](#0-0) ), but the address-definition evaluators in `definition.js` have no equivalent interruption — they only rely on a total operation counter (`MAX_COMPLEXITY`/`MAX_OPS`) that is checked in `validateDefinition`'s evaluate but is entirely absent from `validateAuthentifiers`'s evaluate.

### Finding Description
`validateDefinition`'s `evaluate()` handles the `'address'` op by looking up the referenced address's stored definition and recursing into it synchronously: [2](#0-1) 

This recursion is bounded only by incrementing `complexity`/`count_ops` counters and checking them against `constants.MAX_COMPLEXITY` (100) and `constants.MAX_OPS` (2000): [3](#0-2) 

Crucially, the second, real authentication evaluator `validateAuthentifiers`'s `evaluate()` — which actually verifies signatures against nested address definitions at unit-validation time — has **no complexity/op counters and no recursion-depth check at all**: [4](#0-3) [5](#0-4) 

The code comment above the caller acknowledges the theoretical risk of loops but claims it is mitigated by re-running `validateDefinition` before `evaluate()` on every validation: [6](#0-5) 

This mitigation only limits total node count (≤100) across the *whole* tree traversal, and it uses `needToEvaluateNestedAddress(path)` to skip evaluating nested addresses that are not on the currently-checked authentifier path, meaning many other subtrees are never traversed/counted at all: [7](#0-6) 

Because address definitions can be changed over time via `'address definition change'`/keychange, an attacker fully controls the address chain shape (they can build long chains `A -> address B -> address C -> ... `) without breaking the total 100-op budget, since each hop only needs one `'address'` op to count toward complexity. Neither `evaluate()` implementation employs the `count % 100 === 0` `setImmediate` breathing pattern used elsewhere in the codebase (`aa_validation.js` `validate()` at [8](#0-7)  and `formula/evaluation.js` `evaluate()` at [9](#0-8) ), so every recursive step in `definition.js` adds real, unreleased native call-stack frames (further multiplied by the nested `storage.readDefinitionByAddress` callback and `async.eachSeries` wrapper frames per hop). This mirrors exactly the reported ImageMagick MVG bug class (CWE-674, "failure to limit MVG mutual/circular reference causing stack overflow") — a lack of depth/cycle protection in a recursive definition/reference evaluator leading to uncontrolled recursion and a process crash.

### Impact Explanation
A crafted unit that spends from (or otherwise authenticates via) an address whose definition chains through many nested `['address', ...]` references can drive `validateAuthentifiers`'s unprotected `evaluate()` into deep synchronous recursion. If the recursion depth needed to exhaust the V8 default stack is reachable within the `MAX_COMPLEXITY`/`MAX_OPS` budget once other framing overhead (async wrapper closures, DB-callback frames) is accounted for, this crashes the validating node process (`RangeError: Maximum call stack size exceeded`, uncaught in a synchronous throw context, or a native stack overflow depending on Node/V8 build) — a denial-of-service against any full node, hub, or wallet that validates the crafted unit. This matches the "node unable to confirm new units" / process-crash outcome class that is in scope.

### Likelihood Explanation
Exploitability requires the attacker to construct several addresses on-chain whose definitions reference each other via `'address'` op chains (this is entirely permitted, unprivileged functionality — anyone can create and later redefine an address via keychange to point to another address). No special privileges beyond posting ordinary units are needed. The main uncertainty (not fully verifiable from static review) is whether real Node/V8 stack limits are exceeded within the ~100-op complexity budget once the actual per-hop frame count (each hop = `evaluate` → `storage.readDefinitionByAddress` → callback → `evaluate`, plus `async.eachSeries` wrapper frames for `'or'`/`'and'`/`'r of set'` nesting) is included — this is plausible given how much frame overhead each level adds, but could not be confirmed by executing the code.

### Recommendation
- Add an explicit recursion-depth counter to both `evaluate()` functions in `definition.js` (the one in `validateDefinition` and the one in `validateAuthentifiers`), rejecting once a small max depth (e.g. 10–20) is exceeded, independent of the total complexity/ops counters.
- Add the same `count % N === 0 → setImmediate/setTimeout` call-stack interruption pattern used in `aa_validation.js` and `formula/validation.js` to both `evaluate()` functions in `definition.js`, so long op chains never accumulate unbounded native stack frames.
- Track already-visited addresses (a `Set`) along the current path in both evaluators and reject explicit cycles (`A -> B -> A`) immediately, independent of the complexity budget.
- Add unit tests for deeply chained/circular nested address definitions analogous to the existing `deeply nested array/dictionary/if` formula tests.

### Proof of Concept
Conceptual construction (cannot be executed here, but derivable from the code paths cited above):
1. Create address `A` with definition `['sig', {pubkey: P1}]`.
2. Create address `B` with definition `['address', A]`.
3. Redefine `A` (via a `'change definition'`/keychange authenticated by its current definition) to `['address', B]`, creating a two-node cycle `A -> B -> A`.
4. Post a unit whose author address is `A` (or an outer wrapper address referencing `A`), signed so that `validateAuthentifiers` is invoked to authenticate against `A`'s definition.
5. `validateDefinition`'s `evaluate()` (bounded) will catch this specific 2-cycle quickly via `MAX_COMPLEXITY`, but by chaining many *distinct* non-cyclic addresses (`A1 -> A2 -> ... -> A50`, each a legitimately separate address definition) instead of a literal 2-cycle, an attacker stays under the 100-op complexity limit in `validateDefinition` while still forcing 50+ levels of *synchronous* recursion in `validateAuthentifiers`'s completely unguarded `evaluate()` (`definition.js:646-800`), each level adding multiple stacked closures/callbacks — a scenario the existing complexity/ops counters do not protect against because they only count total nodes, not recursion depth per call stack, and the second `evaluate()` has no counter at all.

### Citations

**File:** formula/validation.js (L272-276)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
```

**File:** definition.js (L94-100)
```javascript
	function needToEvaluateNestedAddress(path){
		if (!arrAuthentifierPaths) // no signatures, just validating a new definition
			return true;
		if (objValidationState.last_ball_mci < constants.skipEvaluationOfUnusedNestedAddressUpgradeMci) // skipping is enabled after this mci
			return true;
		return pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition);
	}
```

**File:** definition.js (L103-111)
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
```

**File:** definition.js (L269-304)
```javascript
			case 'address':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				var other_address = args;
				if (!isValidAddress(other_address))
					return cb("invalid address");
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						console.log("inner address:", arrInnerAddressDefinition);
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					},
					ifDefinitionNotFound: function(definition_chash){
					//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
					//		return cb(null, true);
						var bAllowUnresolvedInnerDefinitions = true;
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function (author) {
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb("failed to calc definition hash of co-author "+other_address+": "+e.message);
						}
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					}
				});
				break;
```

**File:** definition.js (L646-650)
```javascript
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
	
	function evaluate(arr, path, cb2){
		var op = arr[0];
		var args = arr[1];
```

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
```

**File:** definition.js (L1449-1465)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
			if (!bAssetCondition && arrUsedPaths.length !== Object.keys(assocAuthentifiers).length)
				return cb("some authentifiers are not used, res="+res+", used="+arrUsedPaths+", passed="+JSON.stringify(assocAuthentifiers));
			cb(null, res);
		});
	});
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
