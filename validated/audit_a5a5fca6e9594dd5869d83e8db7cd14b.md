## Finding

### Title
Duplicate address-definition check in `validateAuthor()` always rejects units, breaking the fork-resolution mechanism for definitions - (File: `validation.js`)

### Summary
`handleDuplicateAddressDefinition()` in `validation.js` is supposed to conditionally reject a unit that re-declares an address definition, but the guarding `if` statement has been commented out, leaving the `return callback("duplicate definition of address ...")` unconditional. This makes the function always fail, exactly the same bug class as the reported `getPriorVotes()` issue where a validity check was structurally guaranteed to fail and block a legitimate user action.

### Finding Description
`validateAuthor()` calls `validateDefinition()` whenever an author explicitly supplies a `definition` field [1](#0-0) . When `storage.readDefinitionByAddress()` finds that a definition for the address already exists, control passes to `handleDuplicateAddressDefinition()`:

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
``` [2](#0-1) 

The `if (!bNonserial || ...)` guard is commented out, so the `return callback(error)` line executes unconditionally as the very first statement of the function. The remaining code — which compares the definition hashes and, on a match, calls `callback()` with no error, explicitly documented as "let it be for now. Eventually, at most one of the balls will be declared good" — is now unreachable dead code.

This is structurally identical to the reported bug class: a comparison/guard that was meant to gate an error path was broken such that the function *always* returns the error, permanently blocking the legitimate branch (posting a unit whose explicitly-declared definition matches what's already on record, during a nonserial/forked scenario the protocol was designed to tolerate).

### Impact Explanation
Any unprivileged unit poster whose address ends up in a nonserial/forked situation (e.g., two units from the same address racing on different DAG branches, each re-declaring the same address definition explicitly) will have their unit unconditionally marked invalid by `validateAuthor()`, even though the definitions are identical and the protocol's designed behavior (per the code comment) was to accept it and let stability rules resolve which ball wins. Because this rejection happens deterministically in validation (before any DB fork resolution), the affected unit can never become "good," permanently blocking the user's ability to spend from or otherwise use that address in that legitimate scenario — a concrete case of the network being unable to confirm what should be a valid unit.

### Likelihood Explanation
Triggering `ifFound` in `readDefinitionByAddress()` combined with an explicit `definition` field in `objAuthor` is a realistic occurrence for wallets/multi-sig setups that always attach the definition defensively, or during natural nonserial races on an address. No privileged access, malicious peer, or special timing beyond ordinary usage is required — a normal unprivileged unit poster can hit this path simply by posting a unit that redundantly discloses an already-known definition.

### Recommendation
Restore the intended conditional logic, e.g.:
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
so that matching, nonserial redeclarations of the same definition are accepted as originally designed instead of being unconditionally rejected.

### Proof of Concept
1. Address `A` first discloses its definition `D` in unit `U1`.
2. Due to a nonserial fork, another unit `U2` authored by `A` (on a competing branch, `bNonserial = true`, `A` present in `arrAddressesWithForkedPath`) also explicitly includes the same definition `D` as `objAuthor.definition`.
3. `validateAuthor()` → `validateDefinition()` finds the existing definition via `ifFound`, calling `handleDuplicateAddressDefinition(D)`.
4. Because the guarding `if` is commented out, the function immediately returns `callback("duplicate definition of address A, bNonserial=true")`, regardless of the fact that `D === D`.
5. `U2` is rejected outright rather than being accepted and left for the normal stability/fork-resolution process, permanently preventing that legitimate unit from being confirmed. [3](#0-2)

### Citations

**File:** validation.js (L1464-1499)
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
