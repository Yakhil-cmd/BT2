### Title
Legitimate re-declaration of an identical, already-recorded address definition is unconditionally rejected as "duplicate" - (File: validation.js)

### Summary
`validateAuthor`'s `handleDuplicateAddressDefinition` function in `validation.js` unconditionally rejects any unit that explicitly re-includes an author's `definition` field once that address's definition has already been recorded, even when the re-submitted definition is byte-for-byte identical to the one on file and the submitting author is the legitimate owner with valid authentifiers. This is the same root-cause pattern as the reported finding: a content-derived, nonce-less identifier ("has this address's definition already been seen") is used as a hard gate, so a second, entirely valid use of the same content is rejected instead of being accepted as a harmless duplicate.

### Finding Description
`validateAuthor` calls `validateDefinition()` whenever an author explicitly includes a `"definition"` field in a unit [1](#0-0) . It looks up the address's definition via `storage.readDefinitionByAddress`, which has two outcomes: `ifDefinitionNotFound` (first-ever use of this `definition_chash`, i.e., first use of the address) and `ifFound` (a definition for this address has already been recorded) [2](#0-1) .

When `ifFound` fires, `handleDuplicateAddressDefinition` is invoked, and its logic is:

```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	...
	callback(); // let it be for now. Eventually, at most one of the balls will be declared good
}
``` [3](#0-2) 

The intended conditional check (only reject when the unit is nonserial and not already covering a forked path) is commented out, so the function *always* returns the error immediately on the first line, regardless of whether:
- the definition being resent is exactly identical to the previously recorded one, and
- the unit is otherwise perfectly valid (correct authentifiers, correct MCI ordering, no double-spend).

This mirrors the reported bug class exactly: a hash/identity-based "already used" check with no way to distinguish "this is the same legitimate content being resubmitted" from "this is an actual conflict," causing the second (or any subsequent) legitimate submission to be hard-rejected.

A concrete path where this triggers legitimately: a wallet (especially a light client, or any client that doesn't track whether its own definition has already been broadcast/stabilized) composes and signs a unit including the explicit `"definition"` field — this is the normal, expected behavior for any unit spending from a chash-derived address whose definition has not yet been confirmed as known to the network. If, before this second unit is broadcast, an earlier unit from the same address (which also carried the `definition` field) is already processed and its definition recorded, the second unit's `definition` field will trigger `ifFound` → `handleDuplicateAddressDefinition` → unconditional rejection, even though the address, signatures, and definition content are all correct and equal.

### Impact Explanation
This causes legitimate units from real address owners to be rejected/bounced purely due to unlucky ordering of an explicit definition re-declaration, not due to any actual malicious or conflicting content. Per the validation flow, a rejected unit is not admitted to the DAG, so:
- The owner's genuinely valid spend can be dropped, effectively freezing/blocking a legitimate transfer from that address until the wallet is fixed to omit the definition field, matching the report's "It will revert causing good orders not to go through" impact.
- Because the check is content-independent of whether the definition matches (it fails before even comparing content — the `objectHash.getChash160` comparison at lines 1492-1493 is unreachable dead code under the current early-return), this is a strict availability regression for otherwise-valid units, which can manifest for any client/wallet code path that resends `definition` more than once (a common defensive pattern for un-stabilized chash addresses, especially in multi-authored/shared-address flows).

### Likelihood Explanation
Likelihood is moderate-to-high in practice: any wallet, multisig cosigner, or shared-address flow that includes the `definition` field defensively (because it cannot be sure the network has already seen/stabilized the address's definition) will hit this path whenever it happens to send two units carrying `definition` for the same address before the first is confirmed as recorded, or when resending a unit after a race with another unit from the same address. No adversarial user action is even required — it is a normal race condition in composing units from chash-based addresses; an adversarial peer could also intentionally trigger this to grief a target address's follow-up transactions.

### Recommendation
Restore (and correctly implement) the intended conditional logic that was commented out: only treat the re-declaration as an actual conflict when the newly submitted definition differs in content from the one on file, or when it represents a genuine competing/forked definition change. At minimum, the content-hash comparison (`objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition)`) that already exists further down in `handleDuplicateAddressDefinition` should be evaluated before rejecting, so that byte-identical redeclarations of an address's definition are accepted rather than unconditionally bounced.

### Proof of Concept
1. Address `A` is chash-derived from definition `D`.
2. Wallet composes unit `U1` from address `A`, explicitly including `"definition": D` (since it doesn't know whether the network already has `A`'s definition on file). `U1` propagates and is processed; `storage.readDefinitionByAddress` for `A` now returns `ifFound`.
3. The same wallet (or a cosigner in a shared-address flow) composes a second, unrelated but perfectly valid unit `U2` from address `A`, again including `"definition": D` (identical content) because its local view had not yet observed `U1`'s definition being recorded.
4. When `U2` is validated, `validateDefinition()` triggers `ifFound` → `handleDuplicateAddressDefinition(D)` → the function immediately returns `callback("duplicate definition of address A, bNonserial=...")` at line 1488, before ever comparing `D` to the stored definition.
5. `U2` is rejected as invalid despite being a fully legitimate, correctly signed, non-conflicting transaction from the address owner.

### Citations

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
