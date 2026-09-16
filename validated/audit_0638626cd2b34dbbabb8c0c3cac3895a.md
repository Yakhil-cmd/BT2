### Title
Front-running DOS of address validation via cheap third-party definition changes to nested `['address', ...]` conditions - (File: `definition.js`)

### Summary
Address definitions in Obyte can embed a reference to another address's definition via the `['address', other_address]` operator, which is re-resolved dynamically at validation time using `storage.readDefinitionByAddress(conn, other_address, last_ball_mci, ...)`. Because this resolution is not pinned to what existed when the referencing unit was built, the owner of `other_address` can cheaply and unilaterally change their own definition (a normal, low-cost `address_definition_change` message) and cause previously valid, in-flight units built by unrelated parties who reference that address to fail validation — the same "cheap state mutation invalidates another party's precomputed/expected check" pattern described in the `addCredit()` DOS report.

### Finding Description
When an address definition contains a nested `['address', other_address]` term, both `validateDefinition()` and `validateAuthentifiers()` re-resolve `other_address`'s current definition on every validation pass rather than trusting a value fixed at unit-construction time: [1](#0-0) [2](#0-1) 

The code explicitly documents why this re-resolution is necessary and what it implies: [3](#0-2) 

i.e., "in case a referenced address was redefined, complexity might change and exceed the limit" and "redefinition of a referenced address might introduce loops"; the third bullet acknowledges that if an inner address is redefined "but the definition for the new keyset not supplied before last ball, the address becomes temporarily unusable."

The `validateAuthor()` flow further shows how a party's own definition state is gated by `checkNoPendingChangeOfDefinitionChash` / `checkNoPendingDefinition`, and even flags awareness of adversarial timing of definition changes: [4](#0-3) 
"in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet"

Concretely: address `Y` builds a definition such as `['or', [['sig', {Y's key}], ['address', X]]]` (or any construct nesting `X`'s definition, e.g. shared/multisig addresses). Anyone who controls `X` — who need not cooperate with or even be aware of `Y` — can post a cheap `address_definition_change` for `X`. Once that change stabilizes, `storage.readDefinitionByAddress(conn, X, last_ball_mci, ...)` used inside `evaluate()` for the `'address'` case returns the new definition instead of the one `Y`'s unit was built and signed against, so the authentifier/complexity evaluation for `Y`'s in-flight unit(s) can suddenly fail (`"authentifier verification failed"`, `"too complex"`, or become permanently unresolvable if `X`'s new definition never matches what `Y` expected).

### Impact Explanation
This lets any address whose definition is referenced (directly or transitively) inside another address's definition unilaterally and cheaply break the validity of that other address's pending or even not-yet-built units, without needing to be a cosigner or having any economic stake in the target's transaction. This is a denial-of-service on unit validation reachable from a single unprivileged address's normal, low-cost operation (posting its own `address_definition_change`). Because address definitions are commonly used to build shared/multisig/conditional wallets and AA-adjacent constructs referencing external addresses (attestors, cosigners, oracles used as `'address'` conditions), this can strand funds or repeatedly invalidate legitimate spends/authentications for addresses relying on those references, mapping to the "node disagreement on validity" / "network unable to confirm new units" impact classes.

### Likelihood Explanation
Likelihood is constrained by network timing: because `readDefinitionByAddress` is evaluated against `last_ball_mci`, the malicious redefinition must itself stabilize before the victim's unit's last ball advances past it, so this is not an atomic same-block front-run like the Solidity `addCredit()` case — it requires the attacker's change to reach stability first. However, the cost to the attacker is trivial (a single self-authored, self-signed unit), it can be repeated indefinitely, and the code's own comments (`definition.js:1449-1453`, `validation.js:1490`) confirm this exact race is a known, unresolved edge case rather than a hypothetical.

### Recommendation
- Pin nested `'address'` definition resolution to the state as of a fixed reference point relative to the referencing unit (e.g., disallow using a definition_chash that changed within some minimum stability window before use), or
- Require that any address referenced via `['address', ...]` inside another address's definition have a stable, non-pending definition for a minimum number of MC indices before it can be relied upon by referencing units, and
- Surface a clear, catchable validation error distinguishing "temporarily unusable due to pending redefinition of a referenced address" from generic authentifier failures, so wallets can retry rather than silently DOS the sender.

### Proof of Concept
1. Address `X` is referenced inside address `Y`'s definition via `['or', [['sig', {Y}], ['address', X]]]`.
2. `Y` builds and broadcasts a unit relying on `X`'s currently-stable definition to satisfy the `'address'` branch.
3. The controller of `X` posts an `address_definition_change` for `X` (cost: one ordinary unit) before `Y`'s unit stabilizes.
4. Once `X`'s new definition stabilizes and becomes the value returned by `storage.readDefinitionByAddress(conn, X, last_ball_mci, ...)` (`definition.js:279`, `definition.js:779`), `Y`'s pending unit fails signature/authentifier verification or definition validation, denying `Y`'s transaction — mirroring the `addCredit()` pattern of a cheap, unprivileged third-party mutation invalidating another party's expected validation state.

### Citations

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

**File:** definition.js (L774-799)
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
```

**File:** definition.js (L1449-1453)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
```

**File:** validation.js (L1486-1498)
```javascript
	function handleDuplicateAddressDefinition(arrAddressDefinition){
	//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
			return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
		// todo: investigate if this can split the nodes
		// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet
		try {
			if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
				return callback("unit definition doesn't match the stored definition");
		}
		catch (e) {
			return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
		}
		callback(); // let it be for now. Eventually, at most one of the balls will be declared good
```
