Based on my investigation, `hasReferences()` in `definition.js` is a good analog to the CVE-2021-27807 excessive-recursion class. It runs synchronously and recursively over an address/asset definition tree (`or`/`and`/`r of set`/`weighted and`/`not` cases) with **no depth limit and no complexity counter**, unlike every other definition/formula evaluator in this codebase (`validateDefinition`'s `evaluate` in `definition.js` enforces `constants.MAX_COMPLEXITY`/`MAX_OPS`, `validateAADefinition`'s `validate` enforces `MAX_DEPTH` and yields via `setImmediate`, and `formula/validation.js`'s `evaluate` enforces `depth > 100`). [1](#0-0) 

`hasReferences()` is invoked from `writer.js` at the moment a unit is **written to the DB**, i.e., after normal unit validation has already passed — but the definition being hashed there is the raw `author.definition` supplied by the unit poster, and `hasReferences` walks it again with unbounded recursion: [2](#0-1) 

It's also called from `aa_addresses.js` for definitions fetched from light-vendor responses: [3](#0-2) 

Because `validateDefinition`'s `evaluate` bounds `complexity`/`count_ops` (via `constants.MAX_COMPLEXITY`/`MAX_OPS`) but not tree *depth* directly (depth is implicit via complexity, but complexity increments only per node visited in the *async* evaluator, not in `hasReferences`), a deeply left-nested `['not', ['not', ['not', ... ]]]` chain or deeply nested `or`/`and` structure that still satisfies the complexity/ops limits enforced elsewhere could still be deep enough to blow the synchronous call stack in `hasReferences`, given it has its own independent, unbounded recursive traversal with no depth cap or `setImmediate` yielding. This matches the PDFBox bug class (CWE-834, excessive/uncontrolled iteration triggered by attacker-supplied structured input) — although here it manifests as unbounded synchronous recursion (stack-based) rather than a literal infinite loop.

However, I was not able to fully verify from the available index content whether `constants.MAX_COMPLEXITY`/`MAX_DEPTH` checks performed earlier in `validateDefinition`/`validateAADefinition` on the same definition are tight enough to always prevent a nesting depth sufficient to overflow the JS call stack (e.g., whether complexity per level is bounded to 1 op, allowing thousands of `not` nestings under the complexity cap). Confirming the exact numeric value of `constants.MAX_COMPLEXITY`/`MAX_OPS` and reproducing a stack-overflow-causing definition would require running the code, which is outside what I can verify via static search here.

### Title
Unbounded recursive traversal in `hasReferences()` enables stack-overflow DoS via crafted address/asset definition - (File: definition.js)

### Summary
`definition.js`'s `hasReferences(arrDefinition)` recursively walks the `or`/`and`/`r of set`/`weighted and`/`not` structure of an address or asset definition with **no depth limit, no complexity counter, and no async yielding**, unlike the sibling evaluators `validateDefinition.evaluate` (bounded by `constants.MAX_COMPLEXITY`/`MAX_OPS`) and `validateAADefinition.validate` (bounded by `MAX_DEPTH` and `setImmediate` interruption). It is invoked synchronously from `writer.js` while persisting any unit's address definition and from `aa_addresses.js` when caching a light-client-fetched definition.

### Finding Description
`hasReferences` is a plain, non-yielding recursive function [1](#0-0)  that does not track recursion depth or op count, in contrast to `validateDefinition`'s `evaluate`, which explicitly caps complexity and op count per call [4](#0-3) , and `validateAADefinition`'s `validate`, which enforces `MAX_DEPTH` and interrupts the call stack every 100 iterations [5](#0-4) . Because `hasReferences` has an independent traversal path with no such safeguards, an address definition that is just within the complexity/ops limits enforced by `validateDefinition`/`validateAuthentifiers` (or a nested-address definition assembled by chaining multiple ordinary-address definitions via the `address` operator, each individually valid) could still contain enough nested `not`/`or`/`and`/`r of set` levels to exhaust the V8 call stack when `hasReferences` recurses over it during `writer.js`'s persistence step.

### Impact Explanation
A stack overflow inside `hasReferences`, called synchronously during `writer.saveJoint`, would crash the Node.js process handling unit writes (an uncatchable `RangeError: Maximum call stack size exceeded` is not something the surrounding `async`/callback error handling can intercept), causing the node to stop processing/confirming new units — a network-availability impact analogous to the PDFBox infinite-loop DoS.

### Likelihood Explanation
Exploitation requires only posting a unit whose author (or nested/co-author) definition is deeply nested in negation/branching operators. It does not require any privileged position — any unprivileged unit poster who defines their own address (or an asset spending condition) can shape this structure, matching the scope constraint that only unprivileged-reachable paths are in scope. The likelihood depends on whether the pre-existing complexity/op limits in `validateDefinition` (`constants.MAX_COMPLEXITY`, `constants.MAX_OPS`) are loose enough to permit sufficient nesting depth to overflow the stack — this was not conclusively verified from the indexed code (the exact numeric constant values were not located).

### Recommendation
Rewrite `hasReferences` to use an explicit stack-based (iterative) traversal instead of native recursion, or add a depth counter with a hard cap (mirroring `MAX_DEPTH` used in `aa_validation.js`) that rejects definitions exceeding the limit before traversal, ensuring parity with the depth/complexity protections already present in `validateDefinition` and `validateAADefinition`.

### Proof of Concept
Construct an address definition consisting of thousands of nested `['not', [...]]` (or nested `['or', [[...], ['sig', {...}]]]`) wrappers around a valid `sig` leaf, sized to pass `validateDefinition`'s complexity/op checks in `definition.js` (lines 103-111) but deep enough that JavaScript's default call stack (~10-15k frames) is exceeded by `hasReferences`'s per-node recursive call in `definition.js` (lines 1504-1537). Post a unit defining this address; when `writer.saveJoint` calls `Definition.hasReferences(definition)` at `writer.js` line 149, the recursive traversal overflows the stack and crashes the process.

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

**File:** definition.js (L1504-1537)
```javascript
function hasReferences(arrDefinition){
	
	function evaluate(arr){
		var op = arr[0];
		var args = arr[1];
	
		switch(op){
			case 'or':
			case 'and':
				for (var i=0; i<args.length; i++)
					if (evaluate(args[i]))
						return true;
				return false;
				
			case 'r of set':
				for (var i=0; i<args.set.length; i++)
					if (evaluate(args.set[i]))
						return true;
				return false;
				
			case 'weighted and':
				for (var i=0; i<args.set.length; i++)
					if (evaluate(args.set[i].value))
						return true;
				return false;
				
			case 'sig':
			case 'hash':
			case 'cosigned by':
			case 'has definition change':
				return false;
				
			case 'not':
				return evaluate(args);
```

**File:** writer.js (L143-149)
```javascript
			var definition = author.definition;
			var definition_chash = null;
			if (definition){
				// IGNORE for messages out of sequence
				definition_chash = objectHash.getChash160(definition);
				conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO definitions (definition_chash, definition, has_references) VALUES (?,?,?)", 
					[definition_chash, JSON.stringify(definition), Definition.hasReferences(definition) ? 1 : 0]);
```

**File:** aa_addresses.js (L97-108)
```javascript
							var Definition = require("./definition.js");
							var insert_cb = function () { cb(); };
							var strDefinition = JSON.stringify(arrDefinition);
							var bAA = (arrDefinition[0] === 'autonomous agent');
							if (bAA) {
								var base_aa = arrDefinition[1].base_aa;
								rows.push({ address: address, definition: strDefinition, base_aa: base_aa });
								storage.insertAADefinitions(db, [{ address, definition: arrDefinition }], constants.GENESIS_UNIT, 0, 0, false, insert_cb);
							//	db.query("INSERT " + db.getIgnore() + " INTO aa_addresses (address, definition, unit, mci, base_aa) VALUES(?, ?, ?, ?, ?)", [address, strDefinition, constants.GENESIS_UNIT, 0, base_aa], insert_cb);
							}
							else
								db.query("INSERT " + db.getIgnore() + " INTO definitions (definition_chash, definition, has_references) VALUES (?,?,?)", [address, strDefinition, Definition.hasReferences(arrDefinition) ? 1 : 0], insert_cb);
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
