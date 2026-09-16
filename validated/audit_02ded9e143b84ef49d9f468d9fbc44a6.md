### Title
Unbounded recursive expansion in address-definition authentication (no complexity/op/depth limits) - (File: `definition.js`)

### Summary
`validateAuthentifiers()` in `definition.js` evaluates an address's spending-condition tree every time a unit is validated (to check `sig`/`hash`/`address`/`definition template` branches), but unlike its sibling `validateDefinition()` it performs **no complexity accounting, no op-count limit, and no recursion-depth limit** while recursively resolving `['address', …]` and `['definition template', …]` nodes.

### Finding Description
`validateDefinition()`'s `evaluate()` increments `complexity`/`count_ops` on every node and aborts once `constants.MAX_COMPLEXITY` / `constants.MAX_OPS` are exceeded: [1](#0-0) 

This bound is what keeps a *newly defined* address/asset condition small, including the recursive `'address'` case, where the referenced address's current definition is fetched from the DB and evaluated (and thus counted) recursively: [2](#0-1) 

However, `validateAuthentifiers()` — invoked on **every unit** that authenticates against an address (i.e. the hot path reached by any unprivileged unit poster/author) — defines a structurally identical recursive `evaluate()` for `'or'`, `'and'`, `'r of set'`, `'weighted and'`, `'address'`, and `'definition template'`, but with **no complexity, op-count, or depth checks anywhere in this function**: [3](#0-2) 

Critically, the `'address'` branch here re-reads the **current** definition of the nested address at authentication time (`storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, …)`) and recurses into it unconditionally: [4](#0-3) 

and the `'definition template'` branch loads an arbitrary template from the `messages`/`units` tables, fills it with attacker-controlled `params`, and recurses into the filled result — again with no size/complexity bound in this function: [5](#0-4) 

This is the direct analog of the reported ETH-ABI issue: a compact, MAX_COMPLEXITY-bounded definition (validated once, cheaply, at *definition time*) can reference other addresses whose definitions are mutable and independently bounded by MAX_COMPLEXITY *at their own creation time*. Because `validateAuthentifiers` re-resolves and re-evaluates the *live* definition graph on every single authentication without re-checking the aggregate complexity, an attacker can build a chain/DAG of addresses (A → B → C → …, or `'or'`/`'and'` fan-out at each level) where **each individual definition is legal and small** (within `MAX_COMPLEXITY`/`MAX_OPS` at the time it was created) but the **total evaluation work at authentication time grows multiplicatively with each level of nesting/fan-out** (e.g., an `'or'` with `N` `'address'` branches at each of `D` levels yields on the order of `N^D` recursive evaluations, each of which may also trigger a DB query). Because none of these nested definitions were required to know about each other's complexity when created, no single validation step ever sees or rejects the combined blow-up. This mirrors the ZST report's core flaw: a small, spec-legal, per-unit-bounded encoding whose *composition* is unbounded, and the bug is in the consuming code (`validateAuthentifiers`) failing to re-impose the bound that its sibling function (`validateDefinition`) already enforces for the definition-time case.

### Impact Explanation
`validateAuthentifiers` runs on every unit validated by every full node (and is also used for asset conditions via `evaluateAssetCondition`), so a malicious actor could construct a chain/DAG of otherwise-valid, cheaply-defined addresses, then post a single spending unit signed by the outermost address. Validating nodes would be forced to perform an exponential number of recursive evaluations and DB queries (`readDefinitionByAddress` for each `'address'` node, `messages`/`units` lookups for each `'definition template'` node) while checking authentifiers for that one unit, causing severe CPU/DB exhaustion on all nodes attempting to validate/relay the unit — a network-wide denial-of-service on new-unit confirmation, which is one of the accepted impact categories (a network unable to confirm new units).

### Likelihood Explanation
Reaching this path requires only posting units from ordinary addresses: (1) create a chain of small address definitions each referencing other addresses (or using `'or'`/`'and'` fan-out of `'address'` branches), each individually validated and accepted since each is well within `MAX_COMPLEXITY`; (2) post a spending unit signed against the outermost/root address. No special privileges, hub/peer trust, or race conditions are needed — this is achievable by any unprivileged unit poster. The main uncertainty is the exact practical fan-out/depth achievable before other unrelated limits (e.g., unit size, number of authors, `isTooDeeplyNestedOrHasTooManyNodes` on the *unit* JSON itself) kick in, since those limits bound the *unit's own* JSON but not the *externally stored, already-stable* nested address definitions that get pulled in during authentication — those definitions live in the DB and are not part of the new unit's payload size at all, so the JSON node-count / depth caps on the incoming unit do not constrain them.

### Recommendation
Add the same complexity/op-count/depth accounting used in `validateDefinition()` to `validateAuthentifiers()`'s `evaluate()`, tracked across the whole authentication call (including all recursive `'address'` and `'definition template'` resolutions), and abort authentication once a fixed ceiling (e.g. `constants.MAX_COMPLEXITY` / `constants.MAX_OPS`) is exceeded — mirroring the bound already enforced in `definition.js:103-111`. Additionally consider capping recursion depth for nested `'address'` resolution and de-duplicating/caching already-visited address definitions within a single authentication pass to prevent combinatorial (DAG) re-evaluation.

### Proof of Concept
Conceptual construction (not executed, since this requires live network state/DB access to fully realize):
1. Create leaf addresses `L1..Lk` with simple `sig` definitions.
2. Create address `M1 = ['or', [['address', L1], ['address', L2], …]]` — valid and cheap under `MAX_COMPLEXITY` at definition time.
3. Repeat to build `M2 = ['or', [['address', M1a], ['address', M1b], …]]`, and so on for `D` levels, each level individually satisfying `MAX_COMPLEXITY`/`MAX_OPS` in `validateDefinition`.
4. Post a payment unit signed by the top-level address `M_D`.
5. When nodes validate this unit, `validateAuthentifiers` recursively resolves and re-evaluates the entire `M_D → … → L*` graph with no complexity ceiling, causing an evaluation/DB-query count proportional to the branching factor raised to the depth, unlike the definition-time check which bounded only each individual address's own definition. [6](#0-5)

### Citations

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

**File:** definition.js (L646-819)
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
				
			case 'sig':
				// ['sig', {algo: 'secp256k1', pubkey: 'base64'}]
				//console.log(op, path);
				var signature = assocAuthentifiers[path];
				if (!signature)
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'secp256k1';
				if (algo === 'secp256k1'){
					if (objValidationState.bUnsigned && signature[0] === "-") // placeholder signature
						return cb2(true);
					var res = ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey);
					if (!res)
						fatal_error = "bad signature at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported sig algo at path "+path;
					return cb2(false);
				}
				break;
				
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'sha256';
				if (algo === 'sha256'){
					var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
					if (!res)
						fatal_error = "bad hash at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported hash algo at path "+path;
					return cb2(false);
				}
				break;
				
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
