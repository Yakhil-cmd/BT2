### Title
IDOR in `reject_new_shared_address` handler allows any paired device to delete another user's pending multisig address negotiation - ([File: wallet_defined_by_addresses.js])

### Summary
The device-message handler for subject `reject_new_shared_address` deletes a pending shared (multisig) address negotiation identified only by `address_definition_template_chash`, without verifying that the sending device is actually one of the members/participants of that pending shared address.

### Finding Description
In `wallet.js`, the hub message dispatcher validates only that the sender is a known correspondent device and that `address_definition_template_chash` is a syntactically valid address, then immediately calls the deletion routine: [1](#0-0) 

That routine, `deletePendingSharedAddress`, performs unconditional deletes keyed solely by the chash, with no check that `from_address` (the message sender) participates in the corresponding `pending_shared_address_signing_paths` rows: [2](#0-1) 

Contrast this with the sibling flow `cancel_new_wallet` (for keys-based wallets), which does perform an ownership/membership check before deleting: it verifies the sender's `device_address` actually has an `extended_pubkeys` row for that wallet and hasn't already approved before deleting: [3](#0-2) 

The `reject_new_shared_address` path skips this equivalent check entirely. `approvePendingSharedAddress` (the counterpart "approve" flow) does key its `UPDATE` by `device_address=from_address` (so it can only touch the sender's own row), but `deletePendingSharedAddress` deletes the *entire* pending negotiation record and all associated signing-path rows for *all* members, based purely on chash, with no `device_address` filter at all: [4](#0-3) 

This is directly analogous to the AVideo IDOR: the endpoint validates that the caller is *an* authenticated party (a paired correspondent device) but does not verify that the caller has any ownership/membership relationship with the specific targeted resource (the pending shared-address record) before deleting it.

### Impact Explanation
Any correspondent device that has been offered participation in *a* multisig address template (and thus can learn a valid `address_definition_template_chash`, e.g., as one signer among several proposed cosigners) can send `reject_new_shared_address` referencing that same chash and unilaterally wipe out the pending negotiation for *all* other members, even though it only has authority to withdraw its own participation. This is a griefing/denial-of-service primitive against in-progress multisig (shared address) setup: legitimate cosigners who already approved will have their approval state silently discarded on the peer that received the malicious reject, breaking the multi-party address creation protocol without any of the legitimate parties consenting.

However, the blast radius is bounded: the deletion only touches `pending_shared_addresses` / `pending_shared_address_signing_paths`, which are pre-finalization, off-chain, per-device staging tables. Once a shared address is fully approved and promoted into the `shared_addresses` table, this deletion path no longer has any effect on the finalized address, its on-chain outputs, or funds already sent to it. Consequently, while the ownership-check flaw is real and the deletion is unauthorized, it does not translate into fund loss, double-spend, supply inflation, or DAG stability disagreement — it is limited to a denial-of-service against the shared-address creation handshake for parties who are already communicating (paired) with the attacker.

### Likelihood Explanation
Exploitation requires: (1) the attacker to be a correspondent/paired device of the victim (a normal precondition for any wallet-to-wallet device message), and (2) the attacker to know a valid `address_definition_template_chash` for a shared-address negotiation it did not fully consent to abandoning-for-others (achievable simply by being one of several proposed cosigners in a multi-party address template, since the template — and hence the chash — is shared with all proposed members up front). Given these are plausible, low-effort conditions for a participant in a multisig setup, the likelihood of a malicious/rogue cosigner using this path is moderate; likelihood of an unrelated random peer guessing the chash is negligible.

### Recommendation
Add a membership/ownership check in `deletePendingSharedAddress` (or in the `reject_new_shared_address` handler) analogous to `wallet_defined_by_keys.deleteWallet`: verify a `pending_shared_address_signing_paths` row exists for `(definition_template_chash, device_address = from_address)` before performing any delete, and restrict the delete to that member's contribution (or, if full-negotiation cancellation is intended, require that all remaining pending signers be notified/reconciled rather than silently dropping the whole record based on one unauthenticated-for-that-resource party).

### Proof of Concept
1. Device A initiates a 2-of-2 (or N-party) shared address creation via `createNewSharedAddressByTemplate`, sending `create_new_wallet`/offer messages containing the `arrAddressDefinitionTemplate` to devices B and C; each learns `address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate)`.
2. Device B approves via `approve_new_shared_address` (writes its own row).
3. Device C (malicious, not yet consenting to opt out) sends `reject_new_shared_address` with the same `address_definition_template_chash` to Device A.
4. Device A's handler calls `walletDefinedByAddresses.deletePendingSharedAddress(chash)`, which deletes *all* `pending_shared_address_signing_paths` rows (including B's approval) and the `pending_shared_addresses` row for that chash — even though C had no record verified as belonging to it, and B's legitimate approval is wiped without B's consent.

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
