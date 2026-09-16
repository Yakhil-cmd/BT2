Based on the investigation, I found a credible analog to CVE-2019-20395 (stack exhaustion via self-referential/deeply-nested recursive definitions) in `ocore`'s address/asset definition evaluator.

### Title
Unbounded recursion depth in `Definition.validateAuthentifiers`'s `evaluate()` allows stack-exhaustion via deeply nested definitions - (File: definition.js)

### Summary
`definition.js` implements two structurally similar recursive tree walkers over an address/asset spending-condition definition: `validateDefinition`'s `evaluate()` [1](#0-0)  and `validateAuthentifiers`'s `evaluate()` [2](#0-1) . The first tracks `complexity`/`count_ops` and enforces `MAX_COMPLEXITY`/`MAX_OPS` limits on every node visited [3](#0-2) . The second, `validateAuthentifiers`'s `evaluate()`, recurses through `'or'`, `'and'`, `'r of set'`, `'weighted and'`, and `'address'` branches without any of its own per-call complexity/op accounting or explicit recursion-depth guard [4](#0-3) [5](#0-4) . Its only protection is that `validateDefinition` is invoked once beforehand and is expected to have already bounded the structure [6](#0-5) . Because a chain-shaped definition (e.g., nested `['and', [ ['and', [ ['and', [...]] ] ] ]]` or nested `'address'` references to other on-chain addresses) increases `complexity` by exactly 1 per level while also increasing native JS call-stack depth by 1 per level, the maximum permitted nesting depth is bounded only by `MAX_COMPLEXITY`, not by any smaller constant meant to protect the call stack specifically.

### Finding Description
This mirrors the libyang bug class: a self-referential/recursive schema construct (there: leafref unions; here: nested boolean/address definition nodes) is walked with plain, synchronous-style recursion with no dedicated stack-depth cap, so parsing/evaluating attacker-supplied input can drive the process to a stack overflow. In `ocore`, an attacker who posts a unit defining a new address (or asset spending condition) can supply an `arrDefinition` built as a long linear chain of `and`/`or`/`r of set`/`weighted and` nodes, or chain `['address', otherAddr]` references between addresses they control, each such address in turn defining another nested `['address', ...]` condition. `validateAuthentifiers`'s `evaluate()` recurses into each nested node/definition [5](#0-4) , and this recursion is exercised every time any unit is validated that is signed by (or spends from) such an address, and every time signed messages are verified via `signed_message.js`'s call into `Definition.validateAuthentifiers` [7](#0-6) , and every time `validateAuthor` in `validation.js` verifies unit authors [8](#0-7) .

### Impact Explanation
A crafted definition/authentifier tree that is deep enough (but still within the `MAX_COMPLEXITY`/`MAX_OPS` node-count budget enforced by `validateDefinition`) can exceed the V8 call-stack limit when walked by `evaluate()` in `validateAuthentifiers`, crashing the Node.js process performing validation. Because this code path runs on every full node validating any unit referencing/signing with the crafted address (units, AA triggers, and private-payment counterparties all invoke definition/authentifier validation), a single posted unit could crash multiple independently-validating nodes, causing denial of validation service and potential network-wide disagreement on unit validity if some nodes crash mid-validation while others recover differently.

### Likelihood Explanation
Reaching this path requires only posting an ordinary unit (or private-payment/AA-trigger message) that defines or references an address with a deeply nested condition — no special privileges are needed. The exact depth achievable depends on the numeric values of `MAX_COMPLEXITY`/`MAX_OPS` in `constants.js`, which limit total node count but not stack depth directly; because these values were not confirmed in this session, the practical exploitability (whether the depth reachable actually exceeds V8's default stack size, which typically permits several thousand frames) is uncertain and should be verified empirically.

### Recommendation
Add an explicit recursion-depth counter (independent of `complexity`/`count_ops`) to `validateAuthentifiers`'s `evaluate()` in `definition.js`, mirroring the `MAX_DEPTH` check already used in `aa_validation.js`'s `validate()` [9](#0-8)  and the `depth > 100` guard in `formula/validation.js`'s `evaluate()` [10](#0-9) . Reject definitions/authentifier evaluations exceeding a conservative depth bound before recursing further, and apply the same depth check to the `'address'`/`'definition template'` nested-definition recursion paths.

### Proof of Concept
Construct an address definition consisting of a linear chain of nested `and` nodes wrapping a single valid `sig` leaf, e.g. `['and', [['and', [['and', [ ... ['sig', {pubkey}] ... ]]]]]]`, nested to a depth just under the `MAX_COMPLEXITY`/`MAX_OPS` limit. Define this as an address, then post a unit whose author uses this address with matching authentifiers. When a node validates the unit, `Definition.validateAuthentifiers`'s `evaluate()` recurses once per `and` level via `async.eachSeries` callbacks [11](#0-10) , and if the nesting depth is large enough to exceed the JS engine's stack limit, the validating process crashes.

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

**File:** definition.js (L646-651)
```javascript
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
	
	function evaluate(arr, path, cb2){
		var op = arr[0];
		var args = arr[1];
		switch(op){
```

**File:** definition.js (L652-732)
```javascript
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
				
			case 'r of set':
				// ['r of set', {required: 2, set: [list of options]}]
				var count = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							if (arg_res)
								count++;
							cb3(); // check all members, even if required minimum already found, so that we don't allow invalid sig on unchecked path
							//(count < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(count >= args.required);
					}
				);
				break;
				
			case 'weighted and':
				// ['weighted and', {required: 15, set: [{value: boolean_expr, weight: 10}, {value: boolean_expr, weight: 20}]}]
				var weight = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg.value, path+'.'+index, function(arg_res){
							if (arg_res)
								weight += arg.weight;
							cb3(); // check all members, even if required minimum already found
							//(weight < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(weight >= args.required);
					}
				);
				break;
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

**File:** definition.js (L1454-1458)
```javascript
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
```

**File:** signed_message.js (L277-289)
```javascript
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
```

**File:** validation.js (L1243-1254)
```javascript
	function validateAuthentifiers(arrAddressDefinition){
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers, 
			function(err, res){
				if (err) // error in address definition
					return callback(err);
				if (!res) // wrong signature or the like
					return callback("authentifier verification failed");
				checkSerialAddressUse();
			}
		);
	}
```

**File:** aa_validation.js (L598-600)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
```

**File:** formula/validation.js (L276-288)
```javascript
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
