Found a concrete analog: `reject_new_shared_address` allows any paired device to delete any pending multi-sig shared-address proposal it names, with no check that the sender is actually one of the addressed cosigners on that proposal.

### Title
Missing ownership check lets any paired device delete another user's pending shared-address proposal - (File: wallet_defined_by_addresses.js)

### Summary
The Wagtail advisory describes a permission flaw where a crafted request lets a limited-privilege user delete a resource (form submission) that belongs to a scope/page they don't have access to, because the delete handler trusts the caller-supplied identifier without verifying the caller's relationship to the referenced resource. `ocore`'s handler for the `reject_new_shared_address` device message has the same root cause: it deletes a pending multisig address proposal identified only by `address_definition_template_chash`, supplied by the sender, without verifying that the sending device is actually one of the cosigners referenced by that proposal.

### Finding Description
When a device receives a `reject_new_shared_address` message, `wallet.js` only validates that `body.address_definition_template_chash` is a syntactically valid address/hash and then calls `walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash)` directly: [1](#0-0) 

`deletePendingSharedAddress` performs the deletion with zero ownership/membership check against `from_address`: [2](#0-1) 

Compare this with the sibling handler `approve_new_shared_address`, which at least scopes its `UPDATE` to `device_address=from_address` in `approvePendingSharedAddress`: [3](#0-2) 

`deletePendingSharedAddress` has no equivalent `device_address=?` filter — it deletes rows purely by `definition_template_chash`, a value the attacker can learn (e.g., by being invited into one legitimate shared-address proposal, or by brute-guessing/observing hashes exchanged over time) and then replay against any other pending proposal, including ones it was never invited to.

### Impact Explanation
Any correspondent device (a "paired device" in the threat model) can wipe out another user's or group's in-progress multisig/shared-address creation flow by sending a single `reject_new_shared_address` justsaying with a `definition_template_chash` it doesn't own a stake in. This causes denial of onboarding for a shared address: `pending_shared_addresses` and `pending_shared_address_signing_paths` rows are deleted, silently discarding collected co-signer approvals (`address`, `device_addresses_by_relative_signing_paths`) for a wallet/contract other users may already be relying on. Because shared addresses back multisig payment addresses and AA-related wallets, forcing cancellation and data loss on the proposal path can result in stalled fund custody setup, especially in a race where an attacker deletes the proposal moments before it would complete (`approvePendingSharedAddress` checks `rows.length === 0` and silently no-ops "another device rejected the address at the same time"), effectively griefing collaborative wallet formation with no way for the legitimate participants to detect who initiated the cancellation.

### Likelihood Explanation
Exploitation requires only that the attacker be a paired device (any correspondent) of one of the participants and know or guess a `definition_template_chash` — a 160-bit c-hash that is exchanged in cleartext justsaying/pairing messages during legitimate wallet-creation flows (`sendOfferToCreateNewSharedAddress`), so any of the intended cosigners can trivially replay it against other cosigners' devices, or an attacker who is invited to a completely unrelated shared-address proposal learns the format and can supply any hash it intercepts. No cryptographic secret guarding, no signature, and no additional context is required for the delete to succeed.

### Recommendation
Scope the deletion the same way `approvePendingSharedAddress` scopes its update: require that `from_address` (the device sending `reject_new_shared_address`) is actually listed in `pending_shared_address_signing_paths` for the given `definition_template_chash` before deleting, e.g. `DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=? AND device_address=?` and only cascade to deleting the whole `pending_shared_addresses`/remaining signing-path rows once verified that the request came from a legitimate participant of that proposal (or route to per-participant rejection instead of removing the shared proposal outright for everyone based on one caller's say-so).

### Proof of Concept
1. Device A initiates a shared address with cosigners B and C via `createNewSharedAddressByTemplate`, producing `definition_template_chash = H`.
2. Device B (a legitimate participant) learns `H` from the `create_new_shared_address` offer it receives.
3. Device B is separately paired with unrelated Device D and shares `H` with it (or D observes it via any channel), even though D has no legitimate stake in that particular proposal.
4. Device D sends `{"subject":"reject_new_shared_address","body":{"address_definition_template_chash": H}}` to Device A. [1](#0-0) 
5. Device A's handler validates only that `H` is a well-formed address and calls `deletePendingSharedAddress(H)` unconditionally, deleting the proposal state for all real participants (A, B, C) even though D was never part of it. [2](#0-1)

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
