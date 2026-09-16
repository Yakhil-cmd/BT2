### Title
Hardcoded `bAllowUnresolvedInnerDefinitions = true` in `validateDefinition` bypasses intended inner-address resolution check - (File: `definition.js`)

### Summary
In `definition.js`, the `validateDefinition()` function's `'address'` case is supposed to reject a structural/complexity validation when a referenced inner address definition cannot be resolved (neither found on-chain nor supplied by a co-author in the same unit), unless an explicit `objValidationState.bAllowUnresolvedInnerDefinitions` flag permits it. The actual code discards that intended state-driven flag and replaces it with a hardcoded local `true`, so the "cannot resolve, therefore reject" branch is dead code and unresolved inner address references are always silently treated as valid. [1](#0-0) 

### Finding Description
The relevant code:

```js
case 'address':
    ...
    storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
        ifFound: function(arrInnerAddressDefinition){ ... },
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
            ...
        }
    });
    break;
``` [2](#0-1) 

This is the same class of bug as the reported issue: a boolean control flag that is supposed to be threaded through from validation state/caller context is replaced by a constant, so the intended conditional branch (the one that enforces a security check) becomes unreachable, and the code always takes the permissive path. Just as `_balanceAdapters` failed to forward `_withdraw_only` to `_getBalanceTxs` (leaving it at its default `False` and thus permitting unauthorized rebalancing), here `validateDefinition` fails to consult `objValidationState.bAllowUnresolvedInnerDefinitions` and instead hardcodes the permissive value, unconditionally accepting definitions whose inner `['address', X]` reference cannot actually be resolved.

`validateDefinition` is invoked from `validateAuthentifiers` before the actual signature verification proceeds, both when validating a brand-new address definition supplied in a unit and when validating an asset's `issue_condition`/`transfer_condition`. It computes complexity (`complexity++`) and requires that "each branch must have a signature" (`bHasSig`) for the definition to be accepted as well-formed. [3](#0-2) [4](#0-3) 

Because the resolution check is now always satisfied (`cb(null, true)`), any unresolvable `['address', other_address]` node is treated by `validateDefinition` as if it contains a valid signature branch (`bHasSig=true`) reachable through that node, without ever descending into and validating the real inner definition's complexity/op-count/structure. This lets a definition author post structurally malformed, over-complex, or signature-less definitions gated behind an unresolvable inner-address reference and still pass `validateDefinition`'s "has signature" and complexity checks, since the unresolved branch is unconditionally treated as satisfying `bHasSig` without contributing to `complexity`/`count_ops`.

Separately, the actual authorization/signature-checking path, `validateAuthentifiers`'s own `'address'` case, does correctly return `cb2(false)` when the inner address cannot be resolved, so this particular flaw does not by itself allow forging a valid signature. [5](#0-4) 

However, `validateDefinition` is re-run on every use of an address's definition (not just on first use) specifically "because a redefinition of a referenced address might introduce loops that will drive complexity to infinity" or otherwise change validity — this comment makes clear that `validateDefinition`'s complexity/structure re-check is a security-relevant re-verification step, not merely informational. [6](#0-5) 

### Impact Explanation
With the hardcoded bypass, `validateDefinition` can be tricked into accepting a definition/asset condition as structurally valid (satisfying complexity limits and "each branch must have a signature") even though one of its branches is an unresolvable inner address reference that in reality contains no verifiable signature at all. Since `validateDefinition`'s complexity/op accounting for that branch is skipped entirely (the `evaluate()` recursion into the real inner definition never happens), an attacker can construct deeply nested or maliciously structured definitions hidden behind unresolved inner-address references that would otherwise be rejected by the complexity/op-count guards (`MAX_COMPLEXITY`, `MAX_OPS`) — undermining a DoS-prevention control on definition/complexity validation that other parts of the codebase (and the referenced upgrade-mci logic for `skipEvaluationOfUnusedNestedAddressUpgradeMci`) depend on being enforced consistently. This weakens a core invariant network nodes rely on to agree on "is this address definition/asset condition well-formed," which is precisely the kind of node-disagreement-on-validity risk the rules ask to flag.

### Likelihood Explanation
Any unprivileged user can trigger this path simply by posting a unit that defines a new address (or an asset issue/transfer condition) whose oscript includes an `['address', X]` node referencing an address `X` that (a) has never had its definition published on-chain and (b) is not co-signed/co-defined in the same unit. This is entirely reachable from a single posted unit with no special privileges, matching the "unprivileged unit poster" reachability constraint.

### Recommendation
Restore the intended gating logic by reading the flag from `objValidationState` instead of hardcoding it, i.e. replace:
```js
var bAllowUnresolvedInnerDefinitions = true;
```
with
```js
var bAllowUnresolvedInnerDefinitions = !!objValidationState.bAllowUnresolvedInnerDefinitions;
```
(restoring the commented-out `if (objValidationState.bAllowUnresolvedInnerDefinitions) return cb(null, true);` early-return), and audit every caller of `validateAuthentifiers`/`validateDefinition` to explicitly set `bAllowUnresolvedInnerDefinitions` on `objValidationState` only where genuinely intended (e.g., mirroring behavior actually verified against `validateAuthentifiers`'s stricter `'address'` handling), rather than defaulting to permissive.

### Proof of Concept
1. Author a new address `A` with definition `['address', 'B']` where `B` is an address that has never posted any unit/definition on-chain (so `storage.readDefinitionByAddress` calls `ifDefinitionNotFound`), and where the unit defining `A` does not co-author/define `B`.
2. Submit a unit that uses `A`'s definition (e.g., defines it in `authors[].definition`).
3. In `validateAuthentifiers` → `validateDefinition`, the `'address'` case hits `ifDefinitionNotFound`; `arrDefiningAuthors.length === 0`, so with the current hardcoded `bAllowUnresolvedInnerDefinitions = true`, the callback is `cb(null, true)` — validation proceeds as if this branch has a valid signature and its complexity/op-count contribution is skipped, instead of failing with `"definition of inner address B not found"`.
4. Because no real recursive evaluation of `B`'s (nonexistent) definition ever happens, `complexity`/`count_ops` for that branch are undercounted relative to what a real, resolvable nested definition of equivalent depth would cost, letting definitions bypass the intended `MAX_COMPLEXITY`/`MAX_OPS` guard for that portion of the tree while still being accepted as "has a signature."

### Citations

**File:** definition.js (L269-303)
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
```

**File:** definition.js (L620-638)
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
