### Title
Incomplete DoS Mitigation: `definition.js` Signature/Definition Evaluators Lack Event-Loop Yielding Present in Formula Evaluators - (File: definition.js)

### Summary
`formula/evaluation.js` and `formula/validation.js` both defend against long synchronous CPU runs by periodically interrupting their recursive `evaluate()` call chains with `setImmediate`/`setTimeout` every 100 steps (`count % 100 === 0`) [1](#0-0) [2](#0-1) . `definition.js`, which contains the sibling recursive evaluators used to validate address/asset spending-condition definitions and to verify authentifiers/signatures against those definitions, applies only a complexity/op-count cap but never yields the event loop during evaluation — the exact "one entry point patched, sibling entry point missed" pattern described in the FastChat advisory (fix in `api_generate` but not other worker endpoints).

### Finding Description
`validateDefinition()`'s inner `evaluate()` function increments `complexity`/`count_ops` and aborts once `constants.MAX_COMPLEXITY`/`MAX_OPS` is exceeded, but performs no periodic `setImmediate` interruption of the call stack [3](#0-2) . Recursive constructs such as `'or'`, `'and'`, `'r of set'`, and `'weighted and'` walk arbitrarily large branch sets purely through `async.eachSeries`/direct recursive calls [4](#0-3) , and nested `'address'` references recurse into inner definitions read from `storage.readDefinitionByAddress` [5](#0-4) .

The sibling `validateAuthentifiers()` evaluator (used every time a unit author's signature is checked against its address definition — i.e. run for every single posted unit) exhibits the identical gap: no `count`/`setImmediate` throttle exists anywhere in its `evaluate()` function [6](#0-5) , and it too recurses into nested address definitions and asset-condition templates fetched from storage [7](#0-6) .

By contrast, `aa_validation.js`'s definition validator (`validate()` for AA definitions) *does* include the `count % 100 === 0` yield guard [8](#0-7) , and both formula evaluators do as well. This shows the yield-on-recursion mitigation was applied to some evaluation entry points (AA/oscript formulas) but never extended to `definition.js`'s address-definition and authentifier evaluators — an incomplete fix for the same underlying blocking-event-loop bug class, mirroring how FastChat's fix in `base_model_worker.py`'s `api_generate` missed other endpoints reachable by the same attacker.

Because `storage.readDefinitionByAddress` and `db.query` calls can resolve via in-process caches/synchronous-style callback chains rather than always incurring a real async I/O wait, and because `async.eachSeries`/direct recursive JS calls do not yield control back to the event loop on their own, an address definition built up to the `MAX_COMPLEXITY`/`MAX_OPS` budget (bounded, but still potentially large) can execute its full evaluation synchronously within a single tick each time any node validates a unit signed by (or referencing) that address.

### Impact Explanation
`validateAuthentifiers`/`validateDefinition` are invoked during validation of every unit's authors [9](#0-8) , which every full node must perform for every unit broadcast to the network. An unprivileged party can define (or reuse) a complex-but-budget-compliant address definition and repeatedly post units signed by/referencing it; each validating node blocks its single-threaded event loop while walking the definition tree, delaying processing of other units, P2P messages, and RPC/wallet requests on that node. Repeated across the network this degrades or stalls the network's ability to confirm new units in a timely manner — a resource-consumption/availability impact matching CWE-400, consistent with the CVSS vector in the source advisory (`AC:L`, `A:L`, no confidentiality/integrity impact).

### Likelihood Explanation
Likelihood is limited by the fact that `MAX_COMPLEXITY`/`MAX_OPS` in `constants.js` bound the total amount of work per evaluation (their exact numeric values were not confirmed in this investigation — see note below), so a single evaluation cannot run unboundedly. However, because there is no forced yield, any evaluation that is CPU-heavy but within budget will still run as one uninterrupted synchronous block, and since this code path executes for every unit's every author on every node, even a moderate per-call blocking duration is trivially and repeatedly triggerable by an unprivileged unit poster at near-zero cost, unlike operator/hub-only DoS vectors.

### Recommendation
Add the same `count`-based `setImmediate`/`setTimeout` interruption pattern used in `formula/evaluation.js` (`formula/evaluation.js:126-129`) and `aa_validation.js`'s `validate()` (`aa_validation.js:598-603`) to `definition.js`'s `evaluate()` functions inside both `validateDefinition()` and `validateAuthentifiers()`, so that long recursive definition/authentifier evaluations periodically yield to the event loop regardless of whether `MAX_COMPLEXITY`/`MAX_OPS` limits have been reached.

### Proof of Concept
1. Craft an address definition using deeply nested `'or'`/`'and'`/`'r of set'`/`'weighted and'` constructs (and/or nested `'address'` references to other already-known addresses) sized up to (but not exceeding) `constants.MAX_COMPLEXITY`/`MAX_OPS`.
2. Use this address as an author of a unit, or reference it via nested `'address'`/`'definition template'` clauses so it must be resolved during validation.
3. Post the unit to the network repeatedly (from multiple throwaway addresses reusing the same definition-shape). Each validating node will run `validateAuthentifiers`/`validateDefinition`'s `evaluate()` synchronously to completion without ever yielding, blocking that node's event loop for the duration of each unit's validation.

Note: I was unable to confirm the exact numeric values of `constants.MAX_COMPLEXITY`/`MAX_OPS` in this pass, which affects the precise magnitude of the achievable blocking window per call; verifying these constants and empirically measuring per-call evaluation time would be needed to fully quantify severity.

### Citations

**File:** formula/evaluation.js (L126-129)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return setImmediate(evaluate, arr, cb);
```

**File:** formula/validation.js (L272-275)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
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

**File:** definition.js (L187-232)
```javascript
			case 'weighted and':
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["required", "set"]))
					return cb("unknown fields in "+op);
				if (!isPositiveInteger(args.required))
					return cb("required must be positive");
				if (args.required > 1000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("required must be <= 1000");
				if (!Array.isArray(args.set))
					return cb("set must be array");
				if (args.set.length < 2)
					return cb("set must have at least 2 options");
				var weight_of_options_with_sig = 0;
				var total_weight = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb2){
						index++;
						if (!isNonemptyObject(arg))
							return cb2("weighted set element must be a non-empty object");
						if (hasFieldsExcept(arg, ["value", "weight"]))
							return cb2("unknown fields in weighted set element");
						if (!isPositiveInteger(arg.weight))
							return cb2("weight must be positive int");
						if (arg.weight > 1000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
							return cb2("weight must be <= 1000");
						total_weight += arg.weight;
						evaluate(arg.value, path+'.'+index, bInNegation, function(err, bHasSig){
							if (err)
								return cb2(err);
							if (bHasSig)
								weight_of_options_with_sig += arg.weight;
							cb2();
						});
					},
					function(err){
						if (err)
							return cb(err);
						if (args.required > total_weight)
							return cb("required must be <= than total weight");
						var weight_of_options_without_sig = total_weight - weight_of_options_with_sig;
						cb(null, args.required > weight_of_options_without_sig);
					}
				);
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

**File:** definition.js (L646-690)
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

**File:** definition.js (L774-820)
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
				
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
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
