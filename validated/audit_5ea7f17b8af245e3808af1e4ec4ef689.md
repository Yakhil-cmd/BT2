### Title
Unhandled `throw Error("more than 1 address definition")` on attacker-crafted duplicate authors crashes node validation - (File: `definition.js`)

### Summary
Both `validateDefinition()` and `validateAuthentifiers()` in `definition.js` resolve an `['address', other_address]` opcode by looking for an author in the *currently validated unit* whose `address` matches `other_address` and whose `definition`'s chash matches the expected `definition_chash`. The code assumes at most one such author can exist and hard-crashes with `throw Error("more than 1 address definition")` if more than one match is found, instead of returning a validation error through the normal `cb(err)` callback path used everywhere else in this function.

### Finding Description
In the `'address'` opcode handler of `validateDefinition`: [1](#0-0) 
the code filters `objUnit.authors` for entries whose `address` equals `other_address` and whose `definition` hashes to `definition_chash`, then does:
```
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
``` [2](#0-1) 

The identical pattern exists in `validateAuthentifiers`'s `'address'` handler: [3](#0-2) 

`objUnit.authors` is attacker-controlled content of a posted unit. Earlier in `validate()`, the only checks performed on `objUnit.authors` are that it's a non-empty array and that every author address is valid via `isValidAddress` — there is no check anywhere in `validation.js` enforcing that author addresses are unique or sorted: [4](#0-3) [5](#0-4) 

Because nothing prevents a unit from carrying two (or more) author entries with the identical `address` field (each supplying the same `definition` object, so both independently hash to the same `definition_chash`), a nested address-reference (`['address', A]`) inside another author's spending-condition definition referencing address `A` will match both duplicate author entries, driving `arrDefiningAuthors.length` to 2 and hitting the `throw Error`. Unlike every other failure branch in this function, which reports the problem via `cb(err)`/`handleResult(err)` so validation can gracefully reject the unit, this is a raw synchronous `throw` executed from inside an asynchronous callback (`storage.readDefinitionByAddress`'s `ifDefinitionNotFound`), so it cannot be caught by the surrounding `try/catch` in `validate()` and propagates as an unhandled exception.

This mirrors the `CHECK`-fail class in the report: an internal invariant ("author list contains at most one matching definition") is asserted with a hard crash instead of being validated and safely rejected, and the invariant is violated by ordinary externally-supplied input (a posted unit with duplicate co-author entries).

### Impact Explanation
An unprivileged unit poster can construct a multi-authored unit where two authors share the same `address` and identical `definition`, and where one author's spending-condition definition references that shared address via `['address', A]`. When any node validates this unit (`validation.validate`), it triggers the uncaught `throw Error("more than 1 address definition")`, crashing the validating node process instead of rejecting the unit as invalid. Because unit validation is on the hot path for every incoming unit (from network, catch-up, or a directly submitted unit), this allows a single malicious unit to crash any full node that processes it — a network-wide denial-of-service that prevents confirmation of new units, matching the accepted impact category "node unable to confirm new units."

### Likelihood Explanation
Likelihood is high: constructing an authors array with duplicate `address`/`definition` pairs and a definition containing `['address', A]` referencing that duplicated address requires no special privileges, no compromised keys, and no network position — only crafting and broadcasting/posting a single unit is required.

### Recommendation
Replace the `throw Error("more than 1 address definition")` calls in both `validateDefinition` (definition.js, `'address'` opcode) and `validateAuthentifiers` (definition.js, `'address'` opcode) with a graceful validation failure (`return cb("more than 1 address definition")` / `return cb2(false)`), consistent with all other error paths in these functions. Additionally, consider adding an explicit up-front check in `validation.js` that author addresses in `objUnit.authors` are unique, to remove the possibility of duplicate-author units entirely.

### Proof of Concept
1. Craft a unit with two authors both having `address: A`, each supplying an identical `definition` array `D` such that `objectHash.getChash160(D) === A`.
2. Give a third (or one of the two) author's own definition a spending condition `['address', A]` that is not otherwise resolvable via `storage.readDefinitionByAddress` (i.e., address `A` not yet defined on-chain), forcing the `ifDefinitionNotFound` branch.
3. Submit/broadcast this unit for validation.
4. `arrDefiningAuthors` in `definition.js` (`'address'` opcode handler) will match both duplicate author entries for `A`, causing `arrDefiningAuthors.length === 2`, triggering the unhandled `throw Error("more than 1 address definition")` and crashing the node process during `validation.validate`.

### Citations

**File:** definition.js (L288-301)
```javascript
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

**File:** validation.js (L271-272)
```javascript
	if (!isNonemptyArray(objUnit.authors))
		return callbacks.ifUnitError("missing or empty authors array");
```

**File:** validation.js (L321-355)
```javascript
	var arrAuthorAddresses = objUnit.authors ? objUnit.authors.map(function(author) { return author.address; } ) : [];
	
	var objValidationState = {
		arrAdditionalQueries: [],
		arrDoubleSpendInputs: [],
		arrInputKeys: []
	};
	if (bGenesis) {
		objValidationState.last_ball_mci = 0;
		objValidationState.bGenesis = true;
	}
	if (objJoint.unsigned)
		objValidationState.bUnsigned = true;
	objValidationState.bAA = bAA;
	if (bAA)
		objValidationState.aa_mci = aa_mci;
	if (objJoint.ball)
		objValidationState.hasBall = true;

	if (conf.bLight){
		if (!isPositiveInteger(objUnit.timestamp) && !objJoint.unsigned)
			return callbacks.ifJointError("bad timestamp");
		if (objJoint.ball)
			return callbacks.ifJointError(lightStableErrorMessage);
		return objJoint.unsigned 
			? callbacks.ifOkUnsigned(true) 
			: callbacks.ifOk({sequence: 'good', arrDoubleSpendInputs: [], arrAdditionalQueries: []}, function(){});
	}
	else{
		if ("timestamp" in objUnit && !isPositiveInteger(objUnit.timestamp))
			return callbacks.ifJointError("bad timestamp");
	}

	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");
```
