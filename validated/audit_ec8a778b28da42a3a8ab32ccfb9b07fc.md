### Title
Missing authorization check allows any paired device to delete another party's pending shared-address negotiation - (File: wallet_defined_by_addresses.js)

### Summary
The `reject_new_shared_address` device-message handler deletes a pending multisig/shared-address negotiation record using only the `address_definition_template_chash` supplied in the message, without verifying that the sending device (`from_address`) is actually one of the registered member devices for that pending negotiation. This mirrors the XWiki bug class: a state-changing action keyed only by an object ID, missing a check that the requester is authorized to act on that specific object.

### Finding Description
In `wallet.js`, the `reject_new_shared_address` case forwards the attacker-controlled `address_definition_template_chash` straight to `walletDefinedByAddresses.deletePendingSharedAddress` with no ownership validation: [1](#0-0) 

`deletePendingSharedAddress` itself performs an unconditional delete keyed purely by the chash, with no `device_address = from_address` predicate: [2](#0-1) 

This is in clear contrast to the sibling function `approvePendingSharedAddress`, which correctly scopes its `UPDATE` to the requesting device: [3](#0-2) 

Any device address recorded in `correspondent_devices` (i.e., any paired device of the victim, not necessarily a genuine invited member of that specific multisig negotiation) can reach this code path via `handleMessageFromHub` → `doHandle` → the `"reject_new_shared_address"` subject, since the handler only validates that `address_definition_template_chash` looks like a valid address: [4](#0-3) 

Because the delete wipes both `pending_shared_addresses` and `pending_shared_address_signing_paths` for that chash entirely — including approvals already collected from other, legitimate cosigner devices — any paired device that has learned the `address_definition_template_chash` (which is derivable by any device that received the corresponding `create_new_shared_address` offer, since the chash is a deterministic hash of the definition template broadcast to every named member) can unilaterally cancel and erase the shared-address setup being negotiated among other, honest members, even if it is not authorized to do so on their behalf.

### Impact Explanation
An unprivileged paired device (one that is merely a correspondent, not necessarily an authorized member of a given multisig setup) can destroy in-progress multisig/shared-address creation state for other users by supplying only the template chash. This denies legitimate cosigners the ability to complete creation of a jointly controlled address, since all collected approvals and the pending template row are irrecoverably deleted with no re-derivation possible other than restarting the whole multi-party negotiation. This is a functional integrity/availability impact on wallet/address setup analogous to the XWiki filter-preference deletion bug (deleting another party's state object by ID without authorization).

### Likelihood Explanation
Reaching the vulnerable code requires only being an already-paired correspondent device capable of sending arbitrary `handleMessageFromHub` subjects — no special privilege beyond normal device pairing is needed. Learning a valid `address_definition_template_chash` for a specific in-progress negotiation is straightforward for any device that was included as a proposed member (it is trivially derivable from the definition template it receives), making the missing per-device check practically exploitable by a participant/attacker who wants to sabotage the shared-address creation for the remaining members.

### Recommendation
Add an authorization check in `deletePendingSharedAddress` (or before calling it) verifying that `from_address` is actually one of the `device_address` values already registered in `pending_shared_address_signing_paths` for the given `definition_template_chash`, mirroring the existing `device_address=?` scoping used in `approvePendingSharedAddress`. Reject the request if the sender is not a recognized member of that specific pending negotiation.

### Proof of Concept
1. Device A initiates a shared-address definition template involving devices A, B, and C via `createNewSharedAddressByTemplate`, which inserts rows into `pending_shared_addresses`/`pending_shared_address_signing_paths` keyed by `address_definition_template_chash` and sends the offer (including the template) to B and C.
2. Device B computes `address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate)` from the received template (trivial, deterministic).
3. Device B (or any other device paired with A that has obtained the same chash) sends a `"reject_new_shared_address"` device message to A with `{address_definition_template_chash: <chash>}`.
4. `wallet.js`'s handler calls `walletDefinedByAddresses.deletePendingSharedAddress(chash)` unconditionally, deleting the pending negotiation and any approvals already recorded from C, without ever checking that the sender is entitled to cancel it on behalf of the whole group.

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
