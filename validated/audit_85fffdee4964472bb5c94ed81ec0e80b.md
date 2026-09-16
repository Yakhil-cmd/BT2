### Title
Missing Authorization on `reject_new_shared_address` Allows Any Paired Device to Delete Pending Multisig Shared-Address Negotiations (DoS) - ([File: wallet.js])

### Summary
The `reject_new_shared_address` device-message handler deletes a pending shared (multisig) address negotiation identified only by `address_definition_template_chash`, without verifying that the sending device (`from_address`) is actually one of the members participating in that specific pending negotiation. This mirrors the Coolify pattern (CVE-2025-22608) where any authenticated actor could cancel a resource belonging to others by supplying its ID, with no ownership/membership check.

### Finding Description
In the hub message handler, the `reject_new_shared_address` case only validates that `address_definition_template_chash` is a syntactically valid address/hash and then immediately calls `deletePendingSharedAddress`, passing only the chash — `from_address` is never used to scope the deletion: [1](#0-0) 

Compare this with the sibling handler `approve_new_shared_address`, which correctly scopes the DB update to the caller's own device address: [2](#0-1) 

`walletDefinedByAddresses.approvePendingSharedAddress` filters its `UPDATE` by `device_address=?` bound to `from_address`, so only the calling device's own row is touched: [3](#0-2) 

But `deletePendingSharedAddress`, as called both internally (after all legitimate approvals complete) and from the `reject_new_shared_address` handler, takes only the `address_definition_template_chash` argument — no `from_address`/device-membership check is applied before deleting the shared row(s): [4](#0-3) [5](#0-4) 

This means any device that is paired with the local node (a correspondent) and that learns/guesses a valid `address_definition_template_chash` (a deterministic `chash160` of the shared-address definition template — not a secret, and forwarded in plaintext via `create_new_shared_address` offers to every intended cosigner device) can send a single `reject_new_shared_address` message and have the entire multi-party pending shared-address setup deleted from `pending_shared_addresses` / `pending_shared_address_signing_paths` on that node — including approvals already collected from other legitimate cosigners — regardless of whether the sender is one of the intended members of that particular address.

### Impact Explanation
This is a Denial-of-Service against the shared (multisig) address setup process: a party who is not one of the n cosigners of a specific pending shared address (but is a paired correspondent of the victim device and knows or intercepts the deterministic template hash) can unilaterally cancel that negotiation for all legitimate participants, discarding any approvals already gathered. This can be used to repeatedly block legitimate users from ever completing the creation of shared/multisig addresses used for arbiter contracts, joint wallets, or other multi-party wallet definitions — a "network unable to confirm new (shared-address) state" outcome caused entirely by an authenticated-but-unauthorized peer, matching the DoS impact class of the reference CVE.

### Likelihood Explanation
Requires the attacker to already be a paired correspondent device (an unprivileged capability explicitly in scope) and to know a valid `address_definition_template_chash` for a target's pending shared-address negotiation. Since that hash is transmitted to every device address referenced in the template (even indirectly, via forwarding) and there is no secondary secret associated with it, any device that is a member of a *different* branch of a multi-party negotiation, or that otherwise observes the hash, can act on it against parties who never intended it to have that authority. No cryptographic break is needed — only the missing membership check in `deletePendingSharedAddress`/`reject_new_shared_address`.

### Recommendation
In the `reject_new_shared_address` handler, before calling `deletePendingSharedAddress`, verify that `from_address` is present in `pending_shared_address_signing_paths` for the given `definition_template_chash` (the same check already used in `approvePendingSharedAddress`), and either reject/ignore the deletion when the sender is not a participant, or delete only that sender's own approval row and re-evaluate whether the negotiation should still be cancelled.

### Proof of Concept
1. Node A initiates `create_new_shared_address` with a definition template referencing device addresses A, B, and C; the resulting `address_definition_template_chash` is sent as part of the offer to B and C.
2. Device C obtains this `address_definition_template_chash` (via receipt of the offer, forwarding, or a correspondent relationship that surfaces it) but device C is not actually intended to approve/reject this particular negotiation (e.g., it was CC'd via a different template branch, or it is any correspondent that captured the value).
3. C sends `{"cmd": "reject_new_shared_address", "address_definition_template_chash": "<captured chash>"}` to Node A.
4. `walletDefinedByAddresses.deletePendingSharedAddress` deletes the pending shared address and all signing-path rows regardless of C's non-membership, destroying B's already-recorded approval and forcing A and B to restart the multisig setup — a DoS on the legitimate negotiation.

### Citations

**File:** wallet.js (L214-226)
```javascript
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```

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

**File:** wallet_defined_by_addresses.js (L208-210)
```javascript
									async.series(arrQueries, function(){
										deletePendingSharedAddress(address_definition_template_chash);
										// notify all other member-devices about the new shared address they are a part of
```
