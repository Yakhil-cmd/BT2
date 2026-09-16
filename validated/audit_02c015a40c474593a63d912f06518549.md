## Title
Duplicate address-definition redeclaration is always rejected, permanently freezing addresses caught in a serial/nonserial fork - (File: `validation.js`)

## Summary
`validateAuthor()`'s `handleDuplicateAddressDefinition()` helper is supposed to allow a legitimate re-declaration of an address's explicit `definition` array when the address is going through a nonserial (forked) resolution, but only if the address is genuinely nonserial and the new declaration's content-hash matches what was previously stored. Instead, the guard that would let that legitimate case through has been commented out, so the function now *unconditionally* rejects any unit that re-declares an already-known `definition_chash`, even the exact scenario the code was designed to permit.

## Finding Description
`validateDefinition()` calls `handleDuplicateAddressDefinition()` whenever `storage.readDefinitionByAddress()` finds that the `definition_chash` used by `objAuthor` has already been seen before: [1](#0-0) 

The handler itself, however, has the check that would allow the legitimate path commented out: [2](#0-1) 

```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	...
	callback(); // let it be for now. Eventually, at most one of the balls will be declared good
}
```

The commented-out `if` was clearly meant to gate the rejection: only reject as "duplicate" when the address is *not* nonserial (i.e., there is no legitimate reason to re-declare), otherwise fall through, verify the chash still matches, and accept the unit. With the guard disabled, every unit whose author re-declares an already-used `definition_chash` is rejected outright — including the case `checkSerialAddressUse()` deliberately creates: an address that is pushed into `objValidationState.arrAddressesWithForkedPath` and marked `bNonserial = true` after a conflicting/competing unit is detected on the DAG: [3](#0-2) 

There is even a related comment a few lines above acknowledging the danger of this exact failure mode for nonserial addresses: "An uncovered nonserial, if not archived, will block new units from this address forever." [4](#0-3) 

## Impact Explanation
Once an address is involved in a legitimate DAG fork (two competing units authored by the same address, a routine and expected occurrence in a DAG-based ledger, not an attack), any subsequent unit from that address that needs to re-assert its (unchanged) explicit `definition` is permanently rejected by every conforming node, since the check is deterministic and applied identically everywhere. This effectively freezes the address: it can never post another valid unit with an explicit definition again, locking any funds controlled by that address and making the network unable to confirm otherwise-valid units from it. This is a concrete, network-wide, unrecoverable failure — not merely a resource/DoS issue — matching the class of "network unable to confirm new units" / fund-freezing impacts.

## Likelihood Explanation
The trigger condition (two units from the same address competing on the DAG, i.e., a nonserial/forked path) is a normal occurrence that can happen without any malicious intent — e.g., due to network partitions, wallet retries, or race conditions when broadcasting units — and is explicitly anticipated and handled elsewhere in this same function (`checkSerialAddressUse`, `checkNoPendingChangeOfDefinitionChash`, `checkNoPendingDefinition` all have analogous "unless nonserial and forked" escape hatches that are still intact). Only this one handler had its escape hatch disabled, making the bug easy to hit unintentionally and impossible to work around once triggered.

## Recommendation
Restore the intended guard so the duplicate-definition check only rejects genuinely non-nonserial duplicates and otherwise falls through to validate the chash match, consistent with the sibling functions `checkNoPendingChangeOfDefinitionChash` and `checkNoPendingDefinition`:

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

## Proof of Concept
1. Address `A` broadcasts unit `U1` with an explicit `definition` (first use, `definition_chash` = `A`'s address).
2. Before `U1` stabilizes, address `A` broadcasts a second, competing unit `U2` (different parents/content but conflicting on the same address, a routine nonserial scenario) that must also carry the same explicit `definition` (since the address has no other stored definition yet to omit it).
3. `checkSerialAddressUse()` detects the conflict, sets `bNonserial = true` and pushes `A` into `arrAddressesWithForkedPath` for `U2`.
4. `validateDefinition()` runs, finds `readDefinitionByAddress` returns "found" (from `U1`'s pending/stored definition), and calls `handleDuplicateAddressDefinition()`.
5. Because the guard is commented out, `callback("duplicate definition of address ...")` is invoked unconditionally, and `U2` (and every future unit from `A` needing this re-declaration) is rejected by all nodes — permanently, since the condition that would have allowed it can never be reached.

### Citations

**File:** validation.js (L1304-1317)
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
```

**File:** validation.js (L1421-1423)
```javascript
	// This was bad idea.  An uncovered nonserial, if not archived, will block new units from this address forever.
	/*
	function checkNoPendingOrRetrievableNonserialIncluded(){
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
