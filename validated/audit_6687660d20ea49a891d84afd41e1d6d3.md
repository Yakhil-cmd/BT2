## Title
Address definitions can never be legitimately resent, permanently blocking legitimate spends from redefinition-recovered/backup addresses - ([File: validation.js])

### Summary
In `validateAuthor()`'s `handleDuplicateAddressDefinition()`, the guard condition that decides whether to reject a re-supplied address definition was commented out, but the `return callback(...)` statement beneath it was left active and unconditional. As a result, *every* unit whose author explicitly includes a `definition` for an address that the node already has a stored definition for is immediately rejected with `"duplicate definition of address..."`, even when the resent definition is byte-for-byte identical to the one already on file.

### Finding Description
`validateAuthor()` calls `validateDefinition()` whenever an author includes a `definition` field [1](#0-0) . When `storage.readDefinitionByAddress` finds that the address already has a known definition, it invokes `handleDuplicateAddressDefinition(arrAddressDefinition2)` instead of just accepting the (matching) resent definition [2](#0-1) .

Inside `handleDuplicateAddressDefinition`, the intended logic (only reject when the unit is non-serial/forked, i.e. `!bNonserial || arrAddressesWithForkedPath.indexOf(...) === -1`) is commented out, but the `return callback("duplicate definition of address ...")` right after it is not commented out — making it unconditional:

```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
	return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	// todo: investigate if this can split the nodes
	...
	try {
		if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
			return callback("unit definition doesn't match the stored definition");
	}
	...
	callback(); // let it be for now...
}
``` [3](#0-2) 

The code that follows (comparing hashes and allowing the matching definition through with `callback()`) is now unreachable dead code, exactly analogous to the referenced report where a guard/initialization step was neutralized but its accompanying negative side effect stayed active, silently defeating the intended feature (there, no owner was ever set; here, no resent-but-correct definition is ever accepted).

### Impact Explanation
Any unit whose author includes an explicit `definition` object for an address that already has a stored definition is unconditionally rejected as invalid, regardless of whether the definition matches. This affects legitimate flows such as restored/imported wallets, multi-device or co-signing setups, or any wallet implementation that doesn't perfectly track whether it has already omitted the definition on a prior unit and includes it defensively. Such units — and the funds/outputs they intend to spend — become permanently unspendable via that path, and the network is unable to confirm otherwise-valid units from affected addresses, which matches the "AA fund loss or freezing" / "network unable to confirm new units" impact class.

### Likelihood Explanation
This is triggered by ordinary posted units — no privileged access, no malicious peer, and no unusual crafting is required. Any wallet or author that resends its (correct, unchanged) `definition` alongside a unit for an already-known address will hit this path deterministically, making the condition easy to reach in normal usage.

### Recommendation
Restore the intended conditional guard instead of an unconditional rejection, e.g.:
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
so that a matching resent definition on a serial unit is correctly accepted, and only genuinely conflicting/forked definitions are rejected.

### Proof of Concept
1. Address `A` posts a first unit including its `definition` (recorded by all nodes via `storage.readDefinitionByAddress`).
2. Address `A` later posts a second, otherwise fully valid unit that again includes the identical `definition` object (e.g., wallet was reinstalled/restored and doesn't know the definition was already sent, or code defensively resends it).
3. In `validateAuthor()`, `storage.readDefinitionByAddress` finds the existing definition and invokes `ifFound` → `handleDuplicateAddressDefinition(arrAddressDefinition2)` [4](#0-3) .
4. Because the guard is commented out, `handleDuplicateAddressDefinition` immediately calls `callback("duplicate definition of address ...")`, rejecting the unit even though the definitions are identical and the unit would otherwise be perfectly valid [5](#0-4) .
5. The unit fails validation network-wide, and any outputs it was meant to spend remain unusable via that resend path.

### Citations

**File:** validation.js (L1464-1469)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
```

**File:** validation.js (L1479-1483)
```javascript
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
