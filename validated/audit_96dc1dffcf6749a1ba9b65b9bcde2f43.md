### Title
Hardcoded `bAllowUnresolvedInnerDefinitions = true` disables the "definition of inner address not found" check with no opt-out - ([File: definition.js])

### Summary
`validateDefinition()` in `definition.js` contains dead code showing the intended, opt-in-gated behavior for handling an `['address', other_address]` branch whose inner definition cannot be resolved. The proper conditional check (`if (objValidationState.bAllowUnresolvedInnerDefinitions) return cb(null, true);`) is commented out and unconditionally replaced by a hardcoded local `var bAllowUnresolvedInnerDefinitions = true;`. This mirrors the lmdeploy bug class exactly: a security-relevant boolean gate that should require explicit, context-driven opt-in is hardcoded `true` in source, with no caller able to opt out, silently making every validation call trust an unresolved nested address reference as if it were properly proven. [1](#0-0) 

### Finding Description
Inside `validateDefinition`'s `evaluate()`, the `'address'` op recursively verifies inner (delegated) address definitions used inside spending-condition trees (e.g., `["address", "BASE32ADDR"]`). When the referenced address's definition cannot be found in storage (`ifDefinitionNotFound`), the correct/intended logic is to consult `objValidationState.bAllowUnresolvedInnerDefinitions` — a validation-state-scoped flag that should be explicitly set true only in contexts where an unresolved definition is legitimately acceptable (e.g., structural pre-checks unrelated to final signature enforcement). Instead, the code is:

```js
ifDefinitionNotFound: function(definition_chash){
//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
//		return cb(null, true);
	var bAllowUnresolvedInnerDefinitions = true;
	try {
		var arrDefiningAuthors = objUnit.authors.filter(...);
	}
	...
	if (arrDefiningAuthors.length === 0) // no address definition in the current unit
		return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
	...
}
``` [2](#0-1) 

Because `bAllowUnresolvedInnerDefinitions` is now a local hardcoded `true` rather than reading the caller-supplied `objValidationState.bAllowUnresolvedInnerDefinitions`, every call site — regardless of whether it is meant to allow unresolved definitions or not — treats a branch referencing a never-supplied, never-stored inner address definition as `cb(null, true)`. In the context of `validateDefinition`, `true` here specifically means "this branch counts as having a signature" (`bHasSig`), which is checked at the end of the definition walk: `if (!bHasSig && !bAssetCondition) return handleResult("each branch must have a signature");`. [3](#0-2) 

This is structurally identical to the lmdeploy finding: an internal safety switch that used to be conditional on an explicit caller-controlled flag was flattened to an unconditional `true`, eliminating any opt-out and silently expanding the trust boundary for every consumer of `validateDefinition` (address definitions, asset conditions, shared/multi-sig address setup via `wallet_defined_by_addresses.js`, and unit/author validation via `validation.js`'s `validateAuthentifiers` which invokes `validateDefinition` before performing the actual signature checks). [4](#0-3) 

### Impact Explanation
`validateDefinition` is the gate that enforces the invariant "each branch must have a signature" before a definition is accepted as valid for an address, an asset spending condition, or a shared address. With the hardcoded bypass, an attacker can craft a definition tree containing a branch `["address", X]` where `X` is an address with no known definition anywhere (neither previously stored nor supplied as a co-author definition in the same unit). That branch will unconditionally satisfy `bHasSig = true` during structural validation, even though no signature or proof was ever supplied or verified for it. This weakens the address/asset-definition validation invariant relied upon throughout the codebase (definitions and authentifiers are explicitly in scope per the reachable analog surface: "address definitions and authentifiers, hashing and signatures"). Depending on how deeply this structural acceptance interacts with the later real signature-checking pass in `validateAuthentifiers`'s own `evaluate()` (which was not fully traceable within the available tool budget), this can allow definitions/spending conditions to be accepted that appear multi-branch/multi-signature-protected but contain an unauthenticated escape branch, risking unauthorized spending or freezing/disagreement about validity between nodes that hold different partial information about the referenced inner address's definition.

### Likelihood Explanation
Any unprivileged unit poster, asset issuer, or shared-address participant can trigger this path simply by including a nested `["address", other_address]` term inside an address or asset definition where `other_address` is intentionally left undefined anywhere. No special privileges, network position, or malicious peer/node cooperation are required — the poster fully controls the definition content, matching the analog rule's requirement that only single-poster-reachable classes count.

### Recommendation
Restore the intended, non-hardcoded gate: read `objValidationState.bAllowUnresolvedInnerDefinitions` (re-enabling the commented-out check) instead of a local hardcoded `true`, and ensure `objValidationState.bAllowUnresolvedInnerDefinitions` defaults to `false`/`undefined` for all validation call sites that ultimately gate spending authorization (`validateAuthentifiers`), only being explicitly set `true` for call sites where accepting an unresolved definition is provably safe (e.g., informational listing, not authorization). Add a regression test asserting that a definition branch referencing a permanently-unresolved inner address is rejected (or at least does not satisfy the "has signature" requirement) unless the caller explicitly opts in.

### Proof of Concept
1. Construct a definition such as `["or", [["address", "SOME_ADDRESS_WITH_NO_KNOWN_DEFINITION"], ["sig", {pubkey: attacker_pubkey}]]]` (or simply `["address", "SOME_ADDRESS_WITH_NO_KNOWN_DEFINITION"]` alone) and derive its chash as the address/asset-condition definition.
2. Post/validate this definition without ever supplying a definition for `SOME_ADDRESS_WITH_NO_KNOWN_DEFINITION` in storage or as a co-author in the unit.
3. Observe that `validateDefinition`'s `'address'` handler hits `ifDefinitionNotFound`, finds `arrDefiningAuthors.length === 0`, and because `bAllowUnresolvedInnerDefinitions` is hardcoded `true`, returns `cb(null, true)` — satisfying `bHasSig` and passing definition validation — instead of failing with `"definition of inner address ... not found"` as the original (commented-out) logic intended when the flag was not explicitly set. [1](#0-0)

### Citations

**File:** definition.js (L279-303)
```javascript
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

**File:** definition.js (L623-627)
```javascript
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
```

**File:** definition.js (L1454-1465)
```javascript
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
