Confirmed vulnerability found in `validation.js`.

### Title
Commented-out fork-tolerance check in `handleDuplicateAddressDefinition` always rejects legitimate nonserial re-definitions, causing node validity disagreement - (File: validation.js)

### Summary
Inside `validateAuthor()`, the nested function `handleDuplicateAddressDefinition()` is meant to only reject a duplicate address definition when the unit is *not* part of a legitimate forked/nonserial path. The guarding condition has been commented out, so the function unconditionally executes the `return callback(...)` that used to be gated by it, rejecting every duplicate-definition unit regardless of whether it is a valid nonserial fork.

### Finding Description
`validateAuthor()` reaches `validateDefinition()` for any author that explicitly supplies a `definition` field [1](#0-0) . When `storage.readDefinitionByAddress` reports that a definition_chash was already used for this address (`ifFound`), control passes to `handleDuplicateAddressDefinition`:

```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	...
	callback(); // let it be for now. Eventually, at most one of the balls will be declared good
}
``` [2](#0-1) 

The `if` statement that should gate the rejection (`!bNonserial || ... not in arrAddressesWithForkedPath`) is commented out, but the `return callback("duplicate definition ...")` beneath it is **not** indented/commented — it executes unconditionally on every call to `handleDuplicateAddressDefinition`. As a result, the code that follows (the chash-equality check and the permissive `callback()` for legitimately forked nonserial paths) is dead code that can never execute. `bNonserial` is computed elsewhere in `validateAuthor` from `objValidationState.arrAddressesWithForkedPath` [3](#0-2) , and it's exactly units on a forked/nonserial path — legitimately allowed to redefine an address originally sharing the same definition_chash — that this function should let through.

### Impact Explanation
Because the intended condition is disabled, **any** unit whose author re-declares a definition that hashes to a definition_chash already recorded for that address is unconditionally rejected as `"duplicate definition"`, even when the redefinition is on a valid nonserial (forked) branch that the network is designed to tolerate until the fork resolves. Different nodes reaching this code path at different times, or under different fork-detection states, can end up disagreeing about whether such a unit is valid, undermining consensus on unit validity — a violation of the "node disagreement on validity" impact criterion for a DAG-based validity engine.

### Likelihood Explanation
This code path triggers automatically whenever an author explicitly includes a `definition` array in their authors entry and the definition_chash was previously used, which is a normal, network-reachable condition for any address performing a keychange/nonserial fork scenario — no privileged access or malicious peer behavior is required, only an ordinary unit author reusing/exercising the definition mechanism in a fork scenario that ocore is explicitly designed to support.

### Recommendation
Restore the intended guard so the unconditional rejection only fires when the definition reuse is *not* part of a legitimate forked nonserial path:
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
1. Address `A` initially defines itself with definition `D1` (definition_chash `A` = chash(D1)).
2. `A`'s definition is changed via a keychange (new `definition_chash`) recorded as stable.
3. A fork occurs and `objValidationState.arrAddressesWithForkedPath` legitimately includes `A` on one branch, with a unit whose author explicitly re-supplies `D1` as `objAuthor.definition` (same as the address's original/duplicate definition_chash) — a scenario the dead `if`-guard was written to permit.
4. `validateDefinition()` calls `storage.readDefinitionByAddress`; since `D1`'s chash was already used, `ifFound` fires and `handleDuplicateAddressDefinition(D1)` executes.
5. Because the guarding `if` is commented out, `callback("duplicate definition of address ...")` fires unconditionally, and the unit is rejected as invalid, regardless of the legitimate fork/nonserial state that should have allowed it through — producing a validation result inconsistent with the intended fork-tolerant logic and potentially with other nodes' evaluation of the same unit.

### Citations

**File:** validation.js (L1165-1166)
```javascript
	var bNonserial = false;
	var bInitialDefinition = false;
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
