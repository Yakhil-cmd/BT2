### Title
Address definitions delegating via `['address', X]` can be spent without any authentication if the referenced address `X` never posted its own definition on-chain - ([File: definition.js])

### Summary
`validateDefinition()`'s handling of the `'address'` op in `definition.js` always sets `bAllowUnresolvedInnerDefinitions = true` and, when the referenced inner address's definition cannot be found and no co-author in the current unit supplies a matching definition, it resolves the branch as satisfied (`cb(null, true)`) instead of failing. Combined with the "skip evaluation of nested address if no authentifier targets it" optimization, an address whose definition is (or includes as its sole requirement) `['address', X]` can be spent by anyone with zero authentifiers, as long as `X` has never had its definition recorded on the DAG.

### Finding Description
In `definition.js`, the `'address'` case of `evaluate()` resolves nested/delegated address conditions: [1](#0-0) 

The comment (`// if (objValidationState.bAllowUnresolvedInnerDefinitions) return cb(null, true);`) shows this was meant to be conditional, but the code below it hardcodes `var bAllowUnresolvedInnerDefinitions = true;` unconditionally, so whenever `storage.readDefinitionByAddress` reports `ifDefinitionNotFound` and no co-author in the current unit supplies a matching `author.definition` for `X`, the branch resolves to **success** (`cb(null, true)`), i.e. the condition is treated as if it were already proven true, without any cryptographic check.

Before this branch is even evaluated, `needToEvaluateNestedAddress(path)` can short‑circuit evaluation entirely and default to `true` if no authentifier submitted in the unit targets that path: [2](#0-1) 

If the address's whole definition is simply `['address', X]` (a common "delegate spending rights to another address's current/future keyset" pattern used e.g. by shared/multi-party wallets set up via `wallet_defined_by_addresses.js`), then no `sig`/other authentifier op exists anywhere in the definition, so `assocAuthentifiers` for a spending unit from this address is empty, `arrAuthentifierPaths = []`, and `needToEvaluateNestedAddress('r')` returns `false` immediately — the whole definition evaluates to `true` without querying anything. Even when evaluation is forced, the `ifDefinitionNotFound` fallback resolves to `true` as well. Because the `'address'` op never pushes into `arrUsedPaths`, the final "some authentifiers are not used" guard in `validateAuthentifiers` only compares against the (empty) set of authentifiers actually supplied, so it also passes trivially: [3](#0-2) 

The unit-level author check only requires *some* non-empty `authentifiers` object to exist for the unit overall, not that it correspond to any real requirement of this specific address's definition: [4](#0-3) 

Net effect: any address whose definition delegates authority to another address `X` that has not yet posted its own definition_chash-resolving unit on the DAG can be drained by **anyone**, without needing `X`'s or the original creator's private key at all.

### Impact Explanation
This directly enables unauthorized spending of funds. The exact real-world trigger is the multi-party "shared address" feature in `wallet_defined_by_addresses.js`, where users co-sign a definition such as `['and', [['address', partner_address], ['sig', {...}]]]` or, in degenerate/careless setups, `['address', partner_address]` alone, intending `partner_address` to independently gate spending once that partner starts using their address. Until `partner_address` transacts and its definition becomes resolvable on-chain, anyone aware of the shared address's definition (which is inherently shared among co-signers via device messages when the address is created, per `handleNewSharedAddress`) can spend the funds with no valid signature at all. This is a direct loss-of-funds / unauthorized-spending bug, matching the "critical dependency address is 0/unset" bug class in the referenced report: a role that should gate spending (the co-signer's address definition) can be effectively "0" (unresolved), and rather than blocking the action, the code treats it as satisfied.

### Likelihood Explanation
Likelihood is realistic but requires a specific but common ocore pattern: a shared/multi-author address whose spending condition references another address's definition (op `'address'`) as a mandatory branch, where that referenced address has not yet been used/defined on-chain. This is a normal bootstrapping window for shared wallets (a partner address created for the shared wallet but not yet funded/used independently), during which the vulnerability window is open to any party who learns the shared definition (co-owners always know it) or can otherwise obtain it (definitions are also exposed via `light/get_definition` network requests once first disclosed).

### Recommendation
Do not default unresolved inner address definitions to `true`. When the referenced address's definition cannot be found on-chain or from a matching co-author, the branch must be treated as **unproven/false** (or the whole unit deferred/rejected) rather than automatically satisfied, at least when this branch is actually being relied upon as an authentifier path during spending. Restrict the "allow unresolved" behavior strictly to definition-declaration-time complexity checks (`arrAuthentifierPaths === null`), never to actual signature verification.

### Proof of Concept
1. Two co-signers create a shared address with definition `D = ['address', X]` where `X` is a freshly-generated address that has never transacted on the DAG (so `storage.readDefinitionByAddress(X)` returns `ifDefinitionNotFound` and no unit author supplies `X`'s definition).
2. Funds are sent to `chash160(D)`.
3. Any party who knows `D` (both co-signers, by design, know it — it was exchanged when the shared address was created via `handleNewSharedAddress`) constructs a spending unit from `chash160(D)` with an author whose `authentifiers` object is non-empty (can contain an unrelated/dummy path-value that is not required by `D`) but does not supply any authentifier under path `r`, and does not supply `X`'s definition as a co-author.
4. `validateAuthor` → `validateAuthentifiers` → `validateDefinition`'s `'address'` case takes the `ifDefinitionNotFound` branch, hits `bAllowUnresolvedInnerDefinitions = true`, and returns `cb(null, true)`, so path `r` is deemed satisfied.
5. Since `D` requires no `sig` op, `assocAuthentifiers` is empty and `arrUsedPaths.length === Object.keys(assocAuthentifiers).length` (`0 === 0`) also passes, so the unit is accepted as validly authenticated and the funds move — despite no cryptographic proof of control over either the address or `X` ever being checked.

### Citations

**File:** definition.js (L94-100)
```javascript
	function needToEvaluateNestedAddress(path){
		if (!arrAuthentifierPaths) // no signatures, just validating a new definition
			return true;
		if (objValidationState.last_ball_mci < constants.skipEvaluationOfUnusedNestedAddressUpgradeMci) // skipping is enabled after this mci
			return true;
		return pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition);
	}
```

**File:** definition.js (L276-303)
```javascript
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

**File:** validation.js (L1153-1163)
```javascript
		if (hasFieldsExcept(objAuthor, ["address", "authentifiers", "definition"]))
			return callback("unknown fields in author");
		if (!isNonemptyObject(objAuthor.authentifiers) && !objUnit.content_hash)
			return callback("no authentifiers");
		for (var path in objAuthor.authentifiers) {
			if (!isNonemptyString(objAuthor.authentifiers[path]))
				return callback("authentifiers must be nonempty strings");
			if (objAuthor.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return callback("authentifier too long");
		}
	}
```
