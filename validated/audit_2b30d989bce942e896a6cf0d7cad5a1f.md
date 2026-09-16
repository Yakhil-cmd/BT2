The report describes a class of bug where the *effective semantics* of an already-signed/approved action are determined by mutable external state that is resolved only at execution time, and that state is controlled by an unrelated authorization policy. `ocore` has a directly analogous construct in address definitions that reference other addresses.

### Title
Nested `["address", X]` definitions are re-resolved to the referenced address's *current* definition at validation time, letting an unrelated party change the effective spending rules of an already co-signed unit before it is included - ([File: definition.js])

### Summary
An `ocore` address definition can embed another address via the `["address", other_address]` operator. When a unit spending from such a composite address is validated, `other_address`'s definition is looked up live at `objValidationState.last_ball_mci` rather than being fixed to what it was when the co-signers actually produced their authentifiers. Because `other_address` can be redefined at any time by its own, entirely independent set of keyholders/policy (via an `address_definition_change` message), the meaning of a partially-collected, already-signed multi-author unit can change between the moment participants "approve" it (produce authentifiers offline) and the moment it is actually broadcast and validated - exactly the pattern described in the source report where an action's effective execution semantics is decided by mutable state (`authorizedScripts`) resolved at execution instead of being fixed at approval time.

### Finding Description
When validating authentifiers for a definition containing `["address", other_address]`, the code resolves the inner definition with: [1](#0-0) 
and, symmetrically, `validateDefinition` performs the same live lookup when first validating the outer definition tree: [2](#0-1) 

Both calls use `storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, ...)`, i.e. they fetch whichever definition is currently bound to `other_address` as of the unit's `last_ball_mci` - the point of inclusion/validation - not the definition that was in force when the co-signer produced authentifiers for the outer unit. This re-resolution is explicitly acknowledged as intentional in the comment preceding `validateAuthentifiers`: [3](#0-2) 

Separately, `other_address` can redefine itself at any time via an `address_definition_change` message, which is validated independently of the outer composite address and can be authored by a completely different keyholder/policy than the outer definition's other signers: [4](#0-3) 

So a composite/shared address `S = ["and"/"or", [["address", X], <other conditions>]]` has an operative meaning that depends on whatever `X`'s live definition happens to be at the moment `S`'s spending unit is included, not at the moment the other co-signers of `S` signed. If `X`'s controller changes `X`'s definition between the time other parties sign a unit spending from `S` and the time that unit is actually posted/included, the requirements that the signers thought they were satisfying (or refusing to satisfy) can silently change - just as in the Llama report, where whether an approved action executes as `call` or `delegate_call` depends on `authorizedScripts` state that a different, unrelated approval flow can alter after the fact.

### Impact Explanation
If a composite address embeds `["address", X]` as one of several alternative (`or`) or combined (`and`) branches, a party who controls `X` can retime a definition change for `X` to make a previously non-satisfiable branch of `S`'s definition satisfiable (or vice versa) right before the pre-signed/pending unit is included. This can let funds move from the composite/shared address under conditions the other co-signers never actually agreed to when they produced their authentifiers, i.e. unauthorized spending from a shared/multisig-style address. It can also make a unit that was validly signed under the old `X` definition suddenly fail (denial of the intended spend / fund freezing) if the new `X` definition doesn't satisfy the authentifiers that were collected.

### Likelihood Explanation
Exploitation requires a composite address whose definition references another address by address (a supported, documented `oscript` construct used e.g. in shared/arbiter-style addresses), plus timing control over that referenced address's `address_definition_change`. Since address redefinition is a normal, unprivileged operation available to any address owner, and definitions are always re-resolved against the current chain state at `last_ball_mci` (by design, per the comment at definition.js:1449-1453), the window between "co-signers produce authentifiers offline" and "unit gets included" is exploitable by whoever controls the referenced inner address, without needing to compromise any keys.

### Recommendation
For composite definitions that reference another address via `["address", X]`, consider pinning the evaluation to the inner definition that was in force at signing time (or explicitly requiring the referencing unit to embed/commit to a specific `X` definition hash), rather than always resolving to `X`'s live definition at `last_ball_mci`. At minimum, document and warn users/composers that any address referenced via `["address", ...]` inside a shared/multisig definition can unilaterally change the operative meaning of pending, already-collected co-signatures until the spending unit is actually included.

### Proof of Concept
1. Alice creates address `X` with definition `D1 = ["sig", {pubkey: Alice_pubkey}]`.
2. Bob and Alice jointly create shared address `S` with definition `["or", [["and", [["address", X], ["sig", {pubkey: Bob_pubkey}]]], ["sig", {pubkey: Carol_pubkey}]]]` (Alice+Bob branch, or Carol alone).
3. Bob signs (offline) a unit spending a large amount from `S`, expecting the `["address", X]` branch to require Alice's signature under `D1`, and gets Alice's authentifier collected for that branch.
4. Before the unit is broadcast/included, Alice posts an `address_definition_change` for `X` switching to `D2 = ["sig", {pubkey: Mallory_pubkey}]` (per `validation.js` lines 1719-1746, an operation solely under Alice's/`X`'s own control).
5. When the previously-signed unit finally gets validated at some `last_ball_mci` after the change, `definition.js`'s `evaluate` for the `'address'` op (lines 774-782) re-resolves `X`'s definition to `D2`, and the branch's authentifier requirement (and hence its meaning) is now governed by `D2`/Mallory instead of the `D1`/Alice signature scheme that Bob believed he was co-authorizing against.

### Citations

**File:** definition.js (L269-283)
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
```

**File:** definition.js (L774-782)
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

**File:** validation.js (L1719-1746)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();

```
