### Title
Unbounded synchronous recursion in address/asset-condition definition evaluation causes node-crashing stack overflow - (File: definition.js)

### Summary
`Definition.validateDefinition()`'s inner `evaluate()` function in `definition.js` recurses into nested `and`/`or`/`r of set`/`weighted and`/`not` sub-expressions without ever yielding the JS event loop, unlike the sibling parsers in the codebase (`formula/validation.js` and `aa_validation.js`) which explicitly interrupt the call stack every 100 iterations via `setImmediate` specifically "to avoid extra long call stacks to prevent Maximum call stack size exceeded". [1](#0-0) [2](#0-1) 

### Finding Description
`evaluate(arr, path, bInNegation, cb)` in `definition.js` only bounds recursion by a "complexity"/"op count" counter (`MAX_COMPLEXITY` / `MAX_OPS`), not by call-stack depth or explicit yielding: [3](#0-2) 

For terminal ops that resolve synchronously (`sig`, `hash`, `seen address`, `cosigned by`), `cb()` is invoked immediately and synchronously, so `async.eachSeries` over an `and`/`or`/`r of set`/`weighted and` array recurses back into `evaluate()` on the same JS call stack: [4](#0-3) [5](#0-4) 

Because a definition tree can nest these constructs (e.g., `['and', [['and', [...]], sig]]`) up to the `MAX_COMPLEXITY`/`MAX_OPS` budget, an attacker who controls the complexity ceiling can build a definition whose evaluation depth alone (independent of DB round-trips) exceeds V8's default call-stack limit before the counters trip, throwing an uncaught `RangeError: Maximum call stack size exceeded`. This same `evaluate()` is reused for both defining a new address definition and re-validating spending conditions on every unit that uses that address/asset (`validateAuthentifiers` calls `validateDefinition` on every author signature check), and for asset `issue_condition`/`transfer_condition` evaluation: [6](#0-5) [7](#0-6) 

This is the closest structural analog to the CVE-2017-2885 bug class ("stack-based overflow triggered by a specially crafted, attacker-supplied input during parsing/processing"): here the "buffer" is the V8 call stack and the attacker-controlled input is a nested oscript/definition array posted in a normal unit, address definition, or asset condition — reachable by any unprivileged unit poster, not requiring any special node/hub/peer privilege.

I was not able to confirm the exact numeric values of `constants.MAX_COMPLEXITY` and `constants.MAX_OPS` from the index (the grep results returned matches in `constants.js` but the surrounding numeric literals were not returned by my searches), so I cannot state with certainty whether the current complexity ceiling is high enough to reach V8's default stack limit (~10,000–15,000 frames depending on frame size) in a single synchronous chain. This is the main open question that would need to be verified directly against `constants.js` to confirm exploitability versus the counters simply capping recursion below the crash threshold.

### Impact Explanation
If the complexity/ops ceiling permits a synchronous nesting depth deep enough to exhaust the stack, any node that receives and validates such a unit (address definition attached to an authored unit, or an asset's `issue_condition`/`transfer_condition`) will crash the Node.js process with an unhandled `RangeError`. Because `validateDefinition`/`validateAuthentifiers` are invoked during normal unit validation for every full node and light-serving node that processes the unit, this could propagate the crash to many nodes simultaneously as they gossip/relay the same unit — producing a denial-of-service that stops the network from validating/confirming new units. Contrast with `formula/validation.js` and `aa_validation.js`, which already treat this exact bug class as sensitive enough to explicitly comment "avoid extra long call stacks to prevent Maximum call stack size exceeded" — `definition.js`'s `evaluate()` lacks the equivalent protection.

### Likelihood Explanation
Reachable from a single posted unit by any unprivileged author — no special node/peer/hub role required, and no network-timing race needed. The `and`/`or`/`r of set`/`weighted and` ops combined with terminal synchronous ops (`sig`, `hash`) allow constructing arbitrarily deep nesting purely from unit content up to the complexity/op budget. Likelihood ultimately hinges on the (unverified) numeric value of `MAX_COMPLEXITY`/`MAX_OPS` relative to V8's stack-frame budget for this specific call chain — an aspect I could not confirm from the available index.

### Recommendation
Add the same call-stack-interrupt pattern already used elsewhere in the codebase to `evaluate()` in `definition.js`: track a nesting-depth (not just complexity/op) counter, and periodically break the synchronous chain with `setImmediate`/`process.nextTick`, mirroring: [8](#0-7) [9](#0-8) 
Additionally, consider adding an explicit maximum nesting-depth guard (`if (depth > MAX_DEPTH) return cb("max depth reached")`) analogous to `aa_validation.js`'s `MAX_DEPTH` check, independent of the complexity/op counters, since those bound total work but not stack depth for tail-recursive synchronous chains.

### Proof of Concept
Conceptual (pending confirmation of `MAX_COMPLEXITY`/`MAX_OPS` values): construct a deeply right-nested `and` definition such as
```
['and', [['and', [['and', [ ... ['sig', {pubkey:...}], ['sig', {pubkey:...}] ... ]]]]]]
```
nested N levels deep, where N approaches `MAX_COMPLEXITY`/`MAX_OPS`. Post this as an address definition (or as an asset `issue_condition`/`transfer_condition`) in a unit. On validation, `Definition.validateDefinition` → `evaluate()` recurses synchronously through all N `and` levels (each level's `sig` leaves resolve `cb()` synchronously via `async.eachSeries`), and if N exceeds V8's stack-frame limit for this call shape, the validating node crashes with `RangeError: Maximum call stack size exceeded` before the complexity check at line 106 can reject it. This cannot be fully validated without running the code / knowing the exact constant values, which I was unable to retrieve from the indexed excerpt of `constants.js` in this session.

### Citations

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

**File:** aa_validation.js (L598-604)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(validate, obj, name, path, locals, depth, cb, bValueOnly);
		locals = _.cloneDeep(locals);
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

**File:** definition.js (L147-185)
```javascript
			case 'r of set':
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["required", "set"]))
					return cb("unknown fields in "+op);
				if (!isPositiveInteger(args.required))
					return cb("required must be positive");
				if (!Array.isArray(args.set))
					return cb("set must be array");
				if (args.set.length < 2)
					return cb("set must have at least 2 options");
				if (args.required > args.set.length)
					return cb("required must be <= than set length");
				//if (args.required === args.set.length)
				//    return cb("required must be strictly less than set length, use and instead");
				//if (args.required === 1)
				//    return cb("required must be more than 1, use or instead");
				var count_options_with_sig = 0;
				var index = -1;
				async.eachSeries(
					args.set,
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
						var count_options_without_sig = args.set.length - count_options_with_sig;
						cb(null, args.required > count_options_without_sig);
					}
				);
				break;
```

**File:** definition.js (L1443-1466)
```javascript
	if (bAssetCondition && address || !bAssetCondition && this_asset)
		throw Error("incompatible params");
	var arrAuthentifierPaths = bAssetCondition ? null : Object.keys(assocAuthentifiers);
	var fatal_error = null;
	var arrUsedPaths = [];
	
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
}
```

**File:** validation.js (L2815-2827)
```javascript
	async.series([
		function(cb){
			if (!("issue_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.issue_condition, objUnit, objValidationState, null, true, cb);
		},
		function(cb){
			if (!("transfer_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.transfer_condition, objUnit, objValidationState, null, true, cb);
		}
	], callback);
}
```
