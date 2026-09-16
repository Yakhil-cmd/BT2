## Title
`handleDuplicateAddressDefinition()` always rejects unit as invalid due to dead/commented-out guard condition - (File: validation.js)

### Summary
In `validateAuthor()` inside `validation.js`, the helper `handleDuplicateAddressDefinition()` is supposed to only reject a unit when the redisclosed address definition is *not* part of a legitimate nonserial/forked-path resolution. The actual guard condition that should gate this rejection has been commented out, so the function now **unconditionally** returns an error for every unit whose author explicitly discloses a `definition` for an address that already has a stored definition — even in the case the code was explicitly designed to allow.

### Finding Description
`validateDefinition()` calls `storage.readDefinitionByAddress()`, and when a definition is already known for the address it calls `handleDuplicateAddressDefinition(arrAddressDefinition2)`: [1](#0-0) 

The intended logic, as documented by the in-line comment, was to only fail validation when the unit is *not* the special nonserial/forked-path case: [2](#0-1) 

```js
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
}
```

Because the `if (...)` guard is commented out, the `return callback("duplicate definition ...")` statement executes unconditionally on every call, and the remaining logic — which was meant to *accept* a redisclosure that matches the previously stored definition when `bNonserial` is true and the author's address is in `objValidationState.arrAddressesWithForkedPath` (the exact scenario this function exists to handle, per `checkSerialAddressUse()` at `validation.js:1304-1343`) — is dead code that can never run.

This is structurally identical to the reported bug class: an intended boolean guard was accidentally disabled/inverted (via comment removal, analogous to the `!=`/`==` inversion in the external report), so a function that should conditionally succeed now always takes the failure branch.

### Impact Explanation
Any legitimately serial-but-nonserial (forked-path) unit author who needs to explicitly re-disclose their already-known address `definition` — e.g., after their address became `nonserial` due to a competing/conflicting unit — will always have their unit rejected with `"duplicate definition of address..."`, regardless of whether the redisclosed definition correctly matches the stored one. This makes it impossible for such an address to ever confirm a new unit through this recovery path once the nonserial condition mentioned in `checkSerialAddressUse()` is triggered, effectively freezing that address's ability to transact via that path, and causing the network to be unable to confirm otherwise valid units for that address.

### Likelihood Explanation
This path is reachable by any ordinary unit author (no special privileges needed) — merely posting a unit with `author.definition` set for an address whose definition is already known, in the scenario where their prior unit(s) triggered nonserial handling with a forked path is enough. The scenario is explicitly anticipated and documented in the surrounding code, so it is not a hypothetical or edge case but a designed and expected path that is silently broken.

### Recommendation
Restore the intended guard so that the rejection is conditional again, matching the documented design intent:
```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	try {
		if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
			return callback("unit definition doesn't match the stored definition");
	}
	catch (e) {
		return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
	}
	callback();
}
```

### Proof of Concept
1. Author `A` sends unit `U1` that becomes non-serial/forked because a competing unit spends from the same address (`checkSerialAddressUse()` pushes `A` into `objValidationState.arrAddressesWithForkedPath` and sets `bNonserial = true`) — see [3](#0-2) .
2. Author `A` sends a subsequent unit `U2` that explicitly redisclose the (already known) `definition` for address `A`, matching the previously stored `chash160` — the exact case the `todo` comment in `handleDuplicateAddressDefinition` describes.
3. `validateDefinition()` finds the definition already exists via `ifFound` and calls `handleDuplicateAddressDefinition(arrAddressDefinition2)` — [4](#0-3) .
4. Because the guard `if (!bNonserial || ...)` is commented out, `callback("duplicate definition of address ...")` fires unconditionally, and `U2` is rejected as invalid even though its definition correctly matches the stored one and `bNonserial`/`arrAddressesWithForkedPath` conditions were satisfied for acceptance.

### Citations

**File:** validation.js (L1304-1343)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
		});
	}
```

**File:** validation.js (L1464-1484)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
	}
```

**File:** validation.js (L1486-1499)
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
	}
```
