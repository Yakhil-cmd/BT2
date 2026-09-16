### Title
Nested `address` definition re-validation can permanently freeze funds once a referenced address's complexity grows past `MAX_COMPLEXITY` - (File: `definition.js`)

### Summary
An address `A` whose spending condition uses the `['address', B]` op delegates its validity to whatever definition address `B` currently has. `B`'s definition is not fixed at the time `A` is created — it is looked up fresh on **every** subsequent transaction from `A`, and `B`'s current complexity is added to `A`'s. If `B` later redefines itself to a definition that is still valid *on its own* (complexity ≤ `MAX_COMPLEXITY`) but that, combined with `A`'s own operators, pushes `A`'s total complexity above `MAX_COMPLEXITY`, then every future validation attempt for `A` fails with `"complexity exceeded"`. Because this check runs unconditionally inside the very validation path that any transaction from `A` must pass, `A` becomes permanently unable to transact — mirroring the reported HSG bug where a self-referential/irrecoverable revert condition permanently blocks all future operations of the affected entity, with no way to "fix" it because fixing requires exactly the operation that is blocked.

### Finding Description
`validateAuthentifiers()` explicitly documents that address definitions are **re-validated on every spend**, not just once, precisely because referenced addresses can change: [1](#0-0) 

The `evaluate()` complexity counter is incremented and hard-capped inside `validateDefinition`: [2](#0-1) 

and again after the whole tree is walked: [3](#0-2) 

The `'address'` operator recursively pulls in the **current** definition of the referenced address and evaluates it as part of the outer address's own definition, adding its complexity to the running total: [4](#0-3) 

Consequences:
- Address `A` is created with `["address", B]` (or `B` nested inside an `or`/`and`/`r of set`), when `B`'s definition has some complexity `C_B` and `A`'s definition is well under `MAX_COMPLEXITY`.
- Address `B` — completely independently, and with a perfectly valid definition change of its own — later changes its definition (via `address_definition_change`) to a new definition whose complexity `C_B'` is still ≤ `MAX_COMPLEXITY` when validated on its own, but `C_B' + (A's own ops) > MAX_COMPLEXITY`.
- From that point on, **every** attempt to spend from `A` re-runs `validateDefinition` (per the comment at line 1449-1453), which recurses into `B`'s now-heavier definition and returns `"complexity exceeded at ..."`, so `checkTransaction`/`validateAuthor` for `A` always fails.
- There is no way to "undo" this from `A`'s side: `A`'s own definition never changes, and the only way to change it (an `address_definition_change` message from `A`) itself requires `A` to be a valid author of a unit, which requires passing this very same validation. `A`'s funds are frozen permanently, unless `B` is cooperative and reverts its own definition back — which `B`'s owner has no obligation to do and may not even be aware is required.

This is the same bug class as the reported issue: a mandatory, unconditionally-executed validation gate whose failure condition (`count > limit`) can be reached through an action outside the locked entity's control, and whose failure blocks literally every future action of that entity, including the action that would be needed to escape the lock.

### Impact Explanation
Any funds held by address `A` (bytes, private or public assets) become permanently unspendable once triggered. Because `B` can be an arbitrary, unrelated address (not necessarily controlled by the same owner as `A`), this also creates a griefing vector: whoever controls `B` can unilaterally freeze every address that references `B` via `'address'`, `'r of set'`, `'or'`, `'and'`, or `'weighted and'` nesting, simply by growing `B`'s own definition complexity through a legitimate `address_definition_change`. This satisfies the "AA fund loss or freezing" / "node disagreement" criteria — concretely it is unauthorized freezing of assets belonging to the referencing address.

### Likelihood Explanation
Reaching this requires only: (1) creating an address whose definition references another address via the standard `'address'` op — a normal, documented, unprivileged feature (shared/multisig addresses commonly nest other addresses); and (2) the referenced address performing an ordinary, independently-valid `address_definition_change`. No hub, node, or network compromise is needed; both steps are available to any wallet user through normal oscript/address-definition tooling. The complexity accounting (`MAX_COMPLEXITY`, `MAX_OPS`) makes the ceiling deterministic and reachable with moderately nested definitions (`or`/`r of set`/`weighted and` trees), which are also normal usage patterns for multisig/shared wallets.

### Recommendation
- When an address definition contains an `'address'` reference to another address, "snapshot"/pin the complexity budget consumed by the inner definition at the time the outer definition is created (or cap the maximum allowed growth of a referenced address's complexity), rather than unconditionally re-summing the *current* complexity of the referenced address on every future validation.
- Alternatively, disallow `address_definition_change` for an address `B` if the new definition's complexity, combined with any currently known outer definitions referencing `B` via `'address'`, would exceed `MAX_COMPLEXITY` — though this requires tracking reverse references, which is likely impractical; the safer fix is to bound how much an inner reference can contribute rather than re-evaluating it fully every time.
- At minimum, provide an explicit escape path (e.g., an author-signed message type that can bypass full nested-definition re-evaluation for addresses that were valid once but are now blocked solely due to a referenced address's complexity growth), so a legitimately-authored spend from `A` is not permanently rejected due to changes it has no control over.

### Proof of Concept
1. Create address `B` with definition `D0 = ["sig", {pubkey: pkB}]` (complexity ≈ 1).
2. Create address `A` with definition `DA = ["or", [["address", B], ["sig", {pubkey: pkA}]]]`. At creation, `validateDefinition` for `A` computes complexity = (1 for `or`) + (1 for `address`) + `D0`'s complexity (≈1) + (1 for the sibling `sig`) ≈ 4, well under `constants.MAX_COMPLEXITY`.
3. `B`'s owner independently posts an `address_definition_change` changing `B`'s definition to a deeply nested `r of set`/`or` tree `D1` whose own complexity is, say, 90% of `MAX_COMPLEXITY` — a perfectly valid definition on its own, verified via `definition.js:621-638` when `B`'s change is validated.
4. Any subsequent unit spending from `A` triggers `validateAuthor` → `validateAuthentifiers` → `validateDefinition(DA)`, which re-evaluates `["address", B]` (`definition.js:269-304`), pulling in `B`'s current definition `D1`. Total complexity for `A` = `D1`'s complexity + `A`'s own `or`/`sig` overhead, now exceeding `constants.MAX_COMPLEXITY`, and `evaluate()` returns `"complexity exceeded at r.0"` (`definition.js:103-107`).
5. Every future transaction attempting to spend from `A` fails validation the same way; `A`'s balance is permanently locked, and there is no unit `A` can produce (since producing one requires passing this same check) to reverse the situation.

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

**File:** definition.js (L621-638)
```javascript
	var complexity = 0;
	var count_ops = 0;
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
		if (complexity > constants.MAX_COMPLEXITY)
			return handleResult("complexity exceeded");
		if (count_ops > constants.MAX_OPS)
			return handleResult("number of ops exceeded");
		if (objValidationState.max_complexity) {
			objValidationState.complexity += complexity;
			if (objValidationState.complexity > objValidationState.max_complexity)
				return handleResult(`custom complexity limit ${objValidationState.max_complexity} exceeded`);
		}
		handleResult();
	});
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
