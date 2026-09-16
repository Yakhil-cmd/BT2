### Title
Duplicate address definition is always rejected even when identical, unlike ERC4337's idempotent factory requirement - (File: validation.js)

### Summary
`validateDefinition()`/`handleDuplicateAddressDefinition()` in `validation.js` unconditionally rejects any unit whose author includes an explicit `definition` field for an address that already has a stored definition on-chain, even if the newly-submitted definition is byte-for-byte identical to the one already stored. The check that would have allowed this idempotent resubmission is commented out, so a legitimate, harmless re-declaration of an address's own definition is always treated as invalid, mirroring the reported bug class where a deterministic-address "deployment"/registration is rejected instead of being tolerated when it already exists.

### Finding Description
When an author posts a unit with an explicit `definition` field, `validateDefinition()` looks up whether that address's definition has already been established: [1](#0-0) 

If the address's definition is not yet found (`ifDefinitionNotFound`), the code checks that the chash of the submitted definition matches the expected `definition_chash` and accepts it. However, if the definition is already found (`ifFound`), it unconditionally calls `handleDuplicateAddressDefinition`: [2](#0-1) 

The guard that would allow this path to succeed for legitimate resubmissions is commented out:
```
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
```
Because the `if` is commented out, the function body unconditionally executes `return callback("duplicate definition of address ...")` — an error — for *every* case where the address already has a stored definition, regardless of whether the newly submitted definition is identical to the stored one. The subsequent logic that would compare the chash of the found definition against the submitted one and `callback()` (accept) when they match is unreachable dead code.

This is directly analogous to the reported ERC4337 issue: a caller performing an operation that is supposed to be idempotent when the "already deployed"/"already defined" state is detected (re-declaring the same address definition) is instead always reverted/rejected, rather than being tolerated as a no-op success.

### Impact Explanation
Any unprivileged unit author who includes their own address definition in a unit — for instance, a wallet client (especially light wallets, or clients unsure whether the definition has already been confirmed/known to the network) that defensively attaches the definition on a subsequent spend — will have that unit rejected as invalid ("duplicate definition of address ...") even though the definition matches exactly what is already on record. This can cause:
- Rejection of legitimate spending transactions from an address whose definition is already known, effectively freezing/blocking valid transfers of funds from otherwise properly-authorized addresses.
- Divergent behavior between nodes/wallets that always attach definitions defensively (e.g., to be safe against partial propagation) and the validation logic that now always penalizes this practice.

This falls under "AA/wallet fund freezing" and "unauthorized inability to spend" impact categories, since a valid spend, backed by the correct definition and correct signatures, can be denied purely because the definition was resent instead of omitted.

### Likelihood Explanation
Likelihood is moderate: the trigger is a normal, non-malicious action (including one's own address's definition, which matches the currently stored definition, in a payment/AA-trigger unit) that any wallet or AA client could perform, particularly in retry/defensive scenarios. It does not require any privileged access, malicious peer, or network condition — it is reachable purely by a normal unit author. The bug reduces to a straightforward code path that is unconditionally executed due to a commented-out condition, so it will manifest deterministically whenever the scenario occurs.

### Recommendation
Restore (and validate) the intended logic: compare the chash of the previously found definition against the chash of the newly submitted `objAuthor.definition`. If they match, accept the unit (`callback()`), i.e. treat re-declaration of an identical definition as a no-op success (mirroring the ERC4337 expectation of returning the existing account/definition rather than reverting). Only reject when the submitted definition actually differs from what is already stored (a genuine conflicting/duplicate-but-different definition), and route that case, if necessary, through the same nonserial/forked-path handling that the original (now commented-out) code intended:
```diff
function handleDuplicateAddressDefinition(arrAddressDefinition){
-//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
-		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
+	try {
+		if (objectHash.getChash160(arrAddressDefinition) === objectHash.getChash160(objAuthor.definition))
+			return callback(); // identical definition re-declared, treat as no-op
+	} catch (e) {
+		return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
+	}
+	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
+		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	...
}
```

### Proof of Concept
1. Address `A` first uses an explicit definition `D` in unit `U1`; this gets validated via `ifDefinitionNotFound` and stored as `A`'s definition (`storage.readDefinitionByAddress` will now return `ifFound` for `A`).
2. The same address `A` (owned by an honest, unprivileged user) later posts unit `U2` that again explicitly includes the identical definition `D` (e.g., because the wallet defensively always attaches its definition, or because it is unsure the earlier definition has stabilized/propagated).
3. During validation of `U2`, `validateDefinition()` calls `storage.readDefinitionByAddress`, which resolves via `ifFound` (since `D` for `A` is already on record), invoking `handleDuplicateAddressDefinition(D)`.
4. Because the guarding `if` is commented out, `handleDuplicateAddressDefinition` unconditionally returns `callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial)`, causing `U2` to be rejected as invalid — even though `D` submitted in `U2` is identical to the already-stored `D`, and the sender has done nothing wrong. [3](#0-2)

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
