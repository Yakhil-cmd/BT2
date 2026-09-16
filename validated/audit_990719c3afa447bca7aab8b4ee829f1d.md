Confirmed. The key finding: `definition.js` line 623-627 enforces `if (!bHasSig && !bAssetCondition) return handleResult("each branch must have a signature");` — this is the security invariant that every address definition must actually require a real signature somewhere. The `'address'` op at `definition.js:269-304` computes its contribution to `bHasSig` by referencing another address's definition, but when that inner definition cannot be resolved (`ifDefinitionNotFound`), the code hardcodes `bAllowUnresolvedInnerDefinitions = true` (with the configurable check commented out at lines 285-286) and returns `cb(null, true)` — i.e., it *assumes* the unresolved inner address definition contributes a valid signature requirement, without ever having evaluated what that inner definition actually is.

### Title
Unverified assumption that unresolved `'address'` definition reference satisfies the "must have a signature" invariant - (File: definition.js)

### Summary
`definition.js`'s `validateDefinition` requires that every address definition structurally guarantee a real signature is required (`each branch must have a signature`, `definition.js:626-627`), computed by walking the definition tree and returning `bHasSig` for each sub-expression. For the `'address'` op, when the referenced inner address has never posted a definition on the DAG, `ifDefinitionNotFound` at `definition.js:284-297` unconditionally returns `cb(null, true)`, asserting `bHasSig = true` for that branch — without ever inspecting what the inner address's actual definition will turn out to be.

### Finding Description
This mirrors the "assumed success without existence/content check" pattern from the report: instead of a low-level `.call()` returning success for a non-existent contract, here the structural signature-requirement check returns `true` for an address reference whose real definition is completely unknown at validation time (`definition.js:284-297`, especially the commented-out configurable check on lines 285-286 and the hardcoded `var bAllowUnresolvedInnerDefinitions = true;` on line 287). The caller (`evaluate()` for `'or'`/`'and'`/`'r of set'`) treats this branch as if it truly contributes cryptographic authentication weight when composing `count_options_with_sig`, which directly feeds the address-level pass/fail decision on line 626 (`each branch must have a signature`). [1](#0-0) [2](#0-1) 

### Impact Explanation
If the referenced inner address is later defined (e.g., by its owner posting a `definition` message, or by an attacker who controls that address and can choose *any* definition for it, including one that requires **no signature at all**, e.g., `['and', [] ]`-style always-true clauses or a definition with `bAssetCondition`-style bypass), the outer definition — which was validated as "has a signature" — could end up authenticating spends without ever checking a real signature. This directly threatens the "no signature required to spend" invariant that protects every address on the DAG, i.e., potential unauthorized spending from an address that appears (at definition-validation time) to be signature-protected. [3](#0-2) 

### Likelihood Explanation
Note that `validateAuthentifiers` (the actual authentication path used when an author signs and submits a unit, `definition.js:774-800`) does *not* make this optimistic assumption — it returns `cb2(false)` when the inner address definition cannot be found (`definition.js:792-793`), which correctly forces that particular branch to fail authentication if the real definition is not co-supplied. This means the assumption only affects the structural pre-check (`validateDefinition`), not the actual spend authentication in `validateAuthentifiers`. Because of this asymmetry, exploitation would require the two functions' treatment of `bHasSig` vs actual authentication to diverge in an exploitable way (e.g., constructing an address definition where the "sig-bearing" branch is this always-optimistic `'address'` reference and the other required branches evaluate true even without real signatures) — this needs a concrete constructed definition (e.g., `['or', [['address', 'X'], ['and', []]]]`-style patterns) to be proven; I was not able to fully construct and trace such a bypass end-to-end within this investigation.

### Recommendation
Restore the more conservative behavior that was commented out (`definition.js:285-286`), or otherwise refuse to assume `bHasSig = true` for an unresolved `'address'` reference during `validateDefinition`. At minimum, re-validate the structural "has a signature" guarantee at the point the inner address's real definition becomes known (e.g., at spend time via `validateAuthentifiers`, which already correctly fails closed) and ensure no combination of `'or'`/`'and'`/`'r of set'` can pass the top-level `each branch must have a signature` check based on an inner address whose definition is not actually established.

### Proof of Concept
Not independently constructed/verified — would require crafting a concrete address definition combining `['address', 'UNDEFINED_ADDR']` inside an `'or'`/`'and'`/`'r of set'` with other branches, then defining `UNDEFINED_ADDR` post-hoc with a trivially-satisfiable (no real signature) definition, and showing that the outer address can be drained without a genuine signature. This proof of concept is flagged as unverified due to tool/iteration limits.

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
