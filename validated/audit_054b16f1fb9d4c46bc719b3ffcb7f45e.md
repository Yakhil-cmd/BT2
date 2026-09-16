### Title
`handleDuplicateAddressDefinition` always rejects units that repeat an already-known address definition, even for legitimate nonserial (forked-path) resends - (File: `validation.js`)

### Summary
In `validateAuthor`'s inner function `handleDuplicateAddressDefinition`, the guard condition that is supposed to gate the "duplicate definition" rejection is commented out, so the function unconditionally returns an error on every call, regardless of whether the repeated definition matches the one already on file and regardless of whether the unit is on a legitimately nonserial (forked) path. This mirrors the reported bug class: a helper meant to distinguish an allowed case from a disallowed case has its distinguishing condition disabled, so the "update"/"resend" path can never succeed.

### Finding Description
`validateDefinition()` is reached from `checkSerialAddressUse()` → `checkNoPendingChangeOfDefinitionChash()` → `checkNoPendingDefinition()` whenever an author includes an explicit `definition` field in a unit [1](#0-0) . If `storage.readDefinitionByAddress` finds that a definition is already stored for the address, `handleDuplicateAddressDefinition` is invoked with the stored definition [2](#0-1) .

`handleDuplicateAddressDefinition` was clearly designed to only reject the "serial" case (i.e., only error out when the unit is not part of a legitimate nonserial/forked path), and otherwise fall through to compare the chash of the stored definition with the chash of the newly supplied one, accepting the unit if they match (per the comment "let it be for now. Eventually, at most one of the balls will be declared good"):

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
``` [3](#0-2) 

Because the `if (!bNonserial || ...)` line is commented out, the `return callback("duplicate definition of address ...")` on line 1488 executes unconditionally on every invocation — exactly analogous to `updatePoolAddress` unconditionally calling `verifyNewPool`, which reverts whenever the pool already exists. Here, the function unconditionally rejects whenever a definition already exists for the address, even when:
- `bNonserial` is true (the address is on a genuinely forked/conflicting path, which `checkSerialAddressUse` already detected via `findConflictingUnits` and flagged in `objValidationState.arrAddressesWithForkedPath` [4](#0-3) ), and
- the newly supplied definition is byte-for-byte identical (same chash) to the one already stored.

The dead code after the always-taken `return` (the chash-matching check and the accepting `callback()`) can never execute.

### Impact Explanation
Any unprivileged unit poster whose address ends up on a nonserial/forked path (which can occur naturally, e.g., two units posted from the same address before the earlier one stabilizes — not necessarily a malicious act) can never have their unit validated if it repeats the address `definition` field, even though repeating the same, matching definition is exactly the legitimate use case this code was written to allow ("at most one of the balls will be declared good"). This permanently blocks otherwise-valid units for the address, which is a node-disagreement/availability issue for that address: units that should be accepted (matching definition) are always treated as invalid, and the intended mechanism for resolving nonserial address definition to a single good branch cannot function as designed. This can lead to an address becoming unable to post or unable to have its double-spend/fork correctly resolved, i.e., funds tied to that address's chain becoming unusable — a fund-freezing outcome.

### Likelihood Explanation
This code path is reached whenever any address's unit is deemed nonserial due to conflicting units (a normal occurrence with concurrent unit posting, not requiring any privileged access), combined with the unit re-declaring its `definition` field with a value matching the already stored one. Given `bNonserial` handling is a routine part of DAG-based conflict resolution, this is easily triggered without any special conditions or attacker sophistication.

### Recommendation
Re-enable the intended guard so the function only rejects on genuine duplicate-definition abuse and otherwise validates by chash comparison:
```javascript
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
1. Post unit U1 from address A including `definition` D (first use), let it be accepted (A now has D on record).
2. Before U1 stabilizes, post unit U2 from address A (spending a different/conflicting output) that also includes the same `definition` D, causing `findConflictingUnits` to detect a conflict and set `bNonserial = true` for A's path in U2 [5](#0-4) .
3. `checkSerialAddressUse` routes U2 to `validateDefinition`, which finds D already stored via `readDefinitionByAddress` and calls `handleDuplicateAddressDefinition(D)` [6](#0-5) .
4. Because the guarding `if` is commented out, `handleDuplicateAddressDefinition` unconditionally returns `callback("duplicate definition of address ...")`, rejecting U2 even though its definition D exactly matches the stored one and even though `bNonserial` is true — the exact scenario the disabled check was meant to permit.

### Citations

**File:** validation.js (L1304-1327)
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
```

**File:** validation.js (L1464-1483)
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
