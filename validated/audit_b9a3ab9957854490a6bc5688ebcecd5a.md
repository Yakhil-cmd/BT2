## Title
Any paired device can delete another user's pending shared-address setup without authorization checks - (File: wallet_defined_by_addresses.js)

### Summary
The `reject_new_shared_address` message handler in `wallet.js` calls `walletDefinedByAddresses.deletePendingSharedAddress()` using only the `address_definition_template_chash` supplied by the sending device, without ever verifying that the sending device (`from_address`) is actually one of the participants recorded for that template in `pending_shared_address_signing_paths`. This mirrors the reported Astaria bug class: a state-mutating "delete" function reachable by an unprivileged caller with no ownership/authorization check.

### Finding Description
When a device wants to reject participation in a shared (multisig) address being set up, it sends a `reject_new_shared_address` message. The handler only validates that the chash is well-formed and then unconditionally deletes the pending shared address state: [1](#0-0) 

```
case "reject_new_shared_address":
    // {address_definition_template_chash: "BASE32"}
    if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
        return callbacks.ifError("invalid addr def c-hash");
    walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
    callbacks.ifOk();
    break;
```

`deletePendingSharedAddress()` deletes the shared row(s) for that chash from both `pending_shared_address_signing_paths` and `pending_shared_addresses`, unconditionally, for any caller who supplies the chash: [2](#0-1) 

There is no query such as `SELECT 1 FROM pending_shared_address_signing_paths WHERE definition_template_chash=? AND device_address=?` to confirm the requester (`from_address`, derived from the verified device-message signature in `handleMessageFromHub`) is actually a listed cosigner of that pending shared address. Since `deletePendingSharedAddress` is explicitly commented `// unused` and marked as intended for internal use, its exposure through this externally reachable subject handler is unintended, analogous to the `_deleteLienPosition()` function being `public` when it was meant to be internal/gated.

By contrast, the sibling handler `approve_new_shared_address` also does not check membership but only updates a row matched by `(definition_template_chash, device_address)`, which is far less destructive (it can only affect a record keyed to the caller's own device_address). The `reject_new_shared_address` path, however, deletes the shared parent record and ALL associated signing-path rows for ALL participating devices, based solely on the chash, with no ownership binding to `from_address`.

Any device address is treated as a legitimate correspondent for this purpose because `handleMessageFromHub` merely requires the sender to be a known correspondent device (or use a whitelisted subject) — it is not a check that the sender participates in this specific shared address: [3](#0-2) 

Because `address_definition_template_chash` is a deterministic hash of a definition template that is broadcast to every intended cosigner during `createNewSharedAddressByTemplate`, any of the intended cosigners (or any paired correspondent who otherwise learns the chash) can send `reject_new_shared_address` for a chash belonging to a shared address they are not part of / no longer care about, deleting the in-progress multisig setup for every other legitimate participant.

### Impact Explanation
This allows an unprivileged (but paired) correspondent device to unilaterally abort/void another party's in-progress shared/multisig address creation, deleting state belonging to other cosigners without their consent. This is a denial-of-service / griefing vector against address (wallet) definition setup — a case falls squarely in the "address definitions and authentifiers" surface called out as in-scope. It can prevent legitimate users from ever completing setup of a shared custody address, effectively freezing the process by which funds would be secured under that shared/multisig definition.

### Likelihood Explanation
Likelihood is moderate-to-high for any two devices that are already correspondents (paired) of the same set of counterparties — no cryptographic secret beyond a public chash is required, and the request passes the device-message signature/decryption checks that gate all "known correspondent" subjects. Any correspondent who is a party (or becomes aware of the chash via the initial offer broadcast) can trigger the deletion at any time before setup completes.

### Recommendation
Before deleting a pending shared address, verify that `from_address` (the authenticated device address from the signed message) is actually one of the device addresses associated with `definition_template_chash` in `pending_shared_address_signing_paths`, e.g.:
```
db.query("SELECT 1 FROM pending_shared_address_signing_paths WHERE definition_template_chash=? AND device_address=?",
  [address_definition_template_chash, from_address], function(rows){
    if (rows.length === 0) return callbacks.ifError("not a participant of this pending shared address");
    walletDefinedByAddresses.deletePendingSharedAddress(address_definition_template_chash);
    callbacks.ifOk();
});
```
Pass `from_address` into `deletePendingSharedAddress` and perform the authorization check there so any other caller of that function is protected as well.

### Proof of Concept
1. Device A initiates `create_new_shared_address` with a definition template including devices A, B, and C; `pending_shared_addresses`/`pending_shared_address_signing_paths` rows are created and the template (hence its chash) is broadcast to B and C via `sendOfferToCreateNewSharedAddress`.
2. Device C (or any other correspondent who learns the chash, e.g., by observing the broadcast) sends a `reject_new_shared_address` message with that `address_definition_template_chash` to itself/hub even though it did not receive an "approve" flow to complete yet.
3. `wallet.js`'s handler accepts the message purely because C is a known correspondent, and calls `deletePendingSharedAddress(chash)` unconditionally.
4. The pending shared address and all rows for A, B, and C are deleted, silently aborting device A and B's in-progress multisig setup without their consent.

### Citations

**File:** wallet.js (L204-221)
```javascript
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
			
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
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

**File:** wallet_defined_by_addresses.js (L229-234)
```javascript
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
}
```
