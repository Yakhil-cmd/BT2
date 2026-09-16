### Title
Structural validation of an `address` sub-definition treats an unresolved inner address as automatically valid - ([File: definition.js])

### Summary
`validateDefinition()`'s handling of the `['address', 'BASE32']` definition op hard-codes `bAllowUnresolvedInnerDefinitions = true`, so whenever a nested address referenced inside a new address/asset-condition definition has no on-chain definition and is not co-defined by an author in the same unit, the branch is accepted as syntactically valid (`cb(null, true)`) instead of being rejected. This mirrors the low-level-call analog from the external report: an operation targeting a non-existent target (here, a not-yet-defined address) is treated as "success" rather than failing, silently allowing a definition tree to validate around a hole that a later legitimate definition might not actually satisfy.

### Finding Description
`validateDefinition` walks a proposed address (or asset-condition) definition tree to make sure it is well-formed before it is accepted, e.g. when a user posts a new address definition, defines a shared address, or defines an asset's spending conditions. [1](#0-0) 

In the `'address'` case, when the referenced `other_address` has no definition recorded on-chain (`ifDefinitionNotFound`), the code is supposed to only accept the branch as valid if the inner definition is genuinely supplied as a co-author of the current unit (`arrDefiningAuthors`). However, the actual gate is:

```js
ifDefinitionNotFound: function(definition_chash){
//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
//		return cb(null, true);
	var bAllowUnresolvedInnerDefinitions = true;
	...
	if (arrDefiningAuthors.length === 0) // no address definition in the current unit
		return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
``` [2](#0-1) 

The commented-out line shows the intended, conditional behavior (`if (objValidationState.bAllowUnresolvedInnerDefinitions) return cb(null, true);`), which would only permit unresolved references in specific validation contexts (e.g. when pre-validating a brand-new definition template via `wallet_defined_by_addresses.js`'s `validateAddressDefinition`, which explicitly sets `bAllowUnresolvedInnerDefinitions: true` on a fake validation state). Instead, the code now *always* takes the "unresolved = valid" path regardless of the caller's intent, exactly the way a Solidity `call()`/`delegatecall()` to a non-existent address returns `true` for `success` without ever having executed real logic.

`validateDefinition` is invoked from unit/asset validation paths in `validation.js` (author definition validation) and `aa_validation.js` (AA definition validation), where `objValidationState.bAllowUnresolvedInnerDefinitions` is not set. In those normal, security-relevant callers, the hard-coded `true` now unconditionally lets structural validation pass for an address branch referencing a not-yet-existing/definer-less address, instead of enforcing the intended distinction between "pre-flight validation of a not-yet-posted definition" (where unresolved references are legitimately fine) and "on-chain validation of a real definition being registered/used" (where they should not be).

Whether this can be turned into a concrete exploit depends on whether `validateDefinition`'s outcome alone is trusted anywhere as a spend/complexity/signature-sufficiency gate without being re-checked by `validateAuthentifiers` at spend time (the latter correctly returns `cb2(false)` for the same not-found case). Since `validateAuthentifiers` calls `validateDefinition` first and then independently re-evaluates the tree for actual authentication, the spend-time path is not directly bypassed. The primary externally reachable impact is that a poster can register a definition/asset condition whose `address` branch is not actually resolvable/consistent, which passes structural acceptance (`each branch must have a signature` and complexity checks) when it should have been rejected, potentially validating definitions that later behave inconsistently across nodes as the inner address's real definition surfaces (definitions posted afterward may or may not match what different nodes assumed at validation time), a byzantine/consensus-disagreement risk on validity, since some full nodes could have differing/no knowledge of `other_address`'s eventual definition at the time this check runs.

### Impact Explanation
This affects the correctness of definition-tree validation used for addresses and asset spending conditions reachable by any unprivileged unit poster. If nodes evaluate the same nested-`address` branch and reach different notions of whether the reference is "resolved" (e.g., depending on timing of when `other_address`'s definition becomes stable, or on `last_ball_mci`), the hard-coded bypass increases the chance that validation outcomes diverge across nodes, which is the kind of "node disagreement on validity" impact this scan's rules classify as Medium/High. It does not by itself grant unauthorized spending because `validateAuthentifiers`'s runtime evaluation of `'address'` still correctly fails closed (`cb2(false)`) when the definition cannot be resolved.

### Likelihood Explanation
Reachable by any address/asset definer through a normal `definition_chash` first-use flow or asset `definition` message, no privileged role required. The condition triggers whenever an `address`-referencing branch inside a definition points to an address without an existing definition and without a matching co-author `definition` in the same unit, which is not a rare or attacker-only-controlled configuration — it is exactly the situation the commented-out conditional was meant to guard.

### Recommendation
Restore the conditional check that the code originally had (and that is now commented out): only bypass the "not found" failure when `objValidationState.bAllowUnresolvedInnerDefinitions` is explicitly set by the caller (i.e., only in the pre-flight validation flows in `wallet_defined_by_addresses.js`), and make normal on-chain definition/asset validation (`validation.js`, `aa_validation.js`) reject (`cb("definition of inner address "+other_address+" not found")`) when the address's definition cannot be resolved, consistent with the behavior already enforced in `validateAuthentifiers`.

### Proof of Concept
1. A user submits a unit that defines a new address (or an asset with `definer_address` conditions) whose definition tree includes `['address', 'SOME_ADDRESS']`, where `SOME_ADDRESS` has never been defined on-chain and is not a co-author of the unit supplying a matching `definition`.
2. `validateDefinition` reaches the `'address'` case, `storage.readDefinitionByAddress` calls back via `ifDefinitionNotFound`.
3. Because `bAllowUnresolvedInnerDefinitions` is hard-coded to `true`, `arrDefiningAuthors.length === 0` still results in `cb(null, true)`, so the branch — and potentially the whole definition — passes structural validation, even though the reference is genuinely unresolved outside of the deliberate pre-flight validation contexts that the original conditional check was designed to allow this for. [2](#0-1)

### Citations

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
