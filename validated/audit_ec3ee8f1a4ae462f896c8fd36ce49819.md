### Title
Missing Authorization in `reject_new_shared_address` Handler Allows Any Paired Device to Delete Another User's Pending Shared-Address Setup - ([File: wallet_defined_by_addresses.js])

### Summary
The `reject_new_shared_address` device-message handler in `wallet.js` forwards an attacker-controlled `address_definition_template_chash` directly to `walletDefinedByAddresses.deletePendingSharedAddress()` without verifying that the sending device (`from_address`) is actually a participant/cosigner of that particular pending shared-address negotiation. Unlike the sibling code paths for approving a shared address or cancelling a wallet, which both scope their DB writes to rows owned by the sending device, the rejection path performs an unconditional delete keyed only by the hash value, mirroring the CyberPanel `cancelBackupCreation` pattern of trusting an attacker-supplied identifier without an ownership check.

### Finding Description
In `wallet.js`, the `case "reject_new_shared_address"` handler only validates that `body.address_definition_template_chash` is a syntactically valid address/hash before deleting the corresponding pending shared address: [1](#0-0) 

This calls into `deletePendingSharedAddress`, which performs unconditional deletes with no `device_address`/`from_address` predicate at all: [2](#0-1) 

Compare this to the sibling "approve" path, which correctly scopes the mutation to the specific `device_address` requesting the approval: [3](#0-2) 

and to the analogous wallet-cancellation flow in `wallet_defined_by_keys.js`, which explicitly checks that the rejecting device is a genuine, not-yet-approved member of the wallet before performing any deletion: [4](#0-3) 

The `reject_new_shared_address` path has no equivalent membership check — any correspondent device that learns the `address_definition_template_chash` value (e.g. because it was CC'd the offer as one member among several, or observed it via any other means) can delete the shared `pending_shared_addresses` row and all associated `pending_shared_address_signing_paths` rows for every other participant in that multisig/shared-address negotiation, even for signing paths that do not belong to the attacker.

### Impact Explanation
`pending_shared_address_signing_paths` stores approval state and per-device address/signing-path data contributed by *all* cosigning devices during multi-party shared-address (multisig wallet) construction. A single message from any one participant's device deletes this entire cross-tenant state, destroying already-collected approvals belonging to other devices/users and forcing all other parties to redo the negotiation, with no way to detect that a non-owning party triggered it. This is a direct analog to the missing-authorization pattern in CyberPanel's `cancelBackupCreation`: a low-privilege, "authenticated" actor (a paired device / correspondent) can supply an identifier for a resource it does not fully own and unilaterally destroy state belonging to other tenants (other cosigning devices), corrupting/losing collaborative wallet setup data.

### Likelihood Explanation
Exploitation requires only that the attacker be a paired correspondent device that is invited as one of several cosigners in a shared address definition template (a normal, low-privilege position established by the existing pairing/negotiation protocol), and that it know the `address_definition_template_chash`, which is sent to all invited member devices as part of the offer. No additional privilege escalation or race condition is required — a single crafted `reject_new_shared_address` justsaying message suffices.

### Recommendation
Add a membership check to `deletePendingSharedAddress` (or to the `reject_new_shared_address` handler before calling it) that verifies `from_address` is present in `pending_shared_address_signing_paths` for the given `definition_template_chash` before deleting any rows — mirroring the ownership check already performed by `approvePendingSharedAddress` and `wallet_defined_by_keys.deleteWallet`.

### Proof of Concept
1. Device A initiates a multi-signer shared address via `createNewSharedAddressByTemplate`, inviting devices B and C as cosigners; A sends the offer (including `address_definition_template_chash`) to both B and C.
2. Device B legitimately learns `address_definition_template_chash` from the offer message it received.
3. Device C is fully unrelated to B's slot but B, acting maliciously (or a compromised/rogue cosigner), sends a `reject_new_shared_address` justsaying message with the same `address_definition_template_chash` value:
```json
{"subject": "reject_new_shared_address", "body": {"address_definition_template_chash": "<chash learned from offer>"}}
```
4. `wallet.js` case `reject_new_shared_address` calls `walletDefinedByAddresses.deletePendingSharedAddress(chash)` with no check that B is authorized to cancel on behalf of the whole group state; this deletes `pending_shared_addresses` and ALL `pending_shared_address_signing_paths` rows for the chash, including C's and A's already-approved signing path data, even though B's own approval/refusal should logically only affect its own participation slot.

### Citations

**File:** wallet.js (L228-234)
```javascript
			case "reject_new_shared_address":
				// {address_definition_template_chash: "BASE32"}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
				callbacks.ifOk();
				break;
```

**File:** wallet_defined_by_addresses.js (L150-155)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
		function(){
```

**File:** wallet_defined_by_addresses.js (L229-234)
```javascript
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
}
```

**File:** wallet_defined_by_keys.js (L332-337)
```javascript
function deleteWallet(wallet, rejector_device_address, onDone){
	db.query("SELECT approval_date FROM extended_pubkeys WHERE wallet=? AND device_address=?", [wallet, rejector_device_address], function(rows){
		if (rows.length === 0) // you are not a member device
			return onDone();
		if (rows[0].approval_date) // you've already approved this wallet, you can't change your mind
			return onDone();
```
