### Title
Missing Authorization on `reject_new_shared_address` Device Message Allows Any Correspondent to Delete Pending Shared-Address Setup - (File: wallet.js, wallet_defined_by_addresses.js)

### Summary
The device-message handler for `reject_new_shared_address` in `handleMessageFromHub` only validates that `body.address_definition_template_chash` is syntactically a valid address, then unconditionally calls `walletDefinedByAddresses.deletePendingSharedAddress()`. It never checks that `from_address` (the sender of the message, derived from the pairing/device pubkey) is actually one of the device addresses listed in `pending_shared_address_signing_paths` for that `definition_template_chash`. This mirrors the OpenEMR pattern: a caller who is validly authenticated (has a signed/verified device message) but has no relationship to the specific resource can still perform a destructive delete on it.

### Finding Description
`handleMessageFromHub` dispatches the `"reject_new_shared_address"` subject as follows: [1](#0-0) 

which calls into: [2](#0-1) 

`deletePendingSharedAddress` performs unconditional `DELETE FROM pending_shared_address_signing_paths` and `DELETE FROM pending_shared_addresses` keyed solely on `definition_template_chash`, with no `device_address`/`from_address` predicate anywhere in the query. There is no lookup to confirm the sender is one of the members recorded for that pending address (as is done, correctly, in the analogous `approve_new_shared_address` path, which at least restricts the `UPDATE` to `WHERE definition_template_chash=? AND device_address=?` — see `approvePendingSharedAddress`, `wallet_defined_by_addresses.js:150-155`). The reject path has no equivalent scoping at all.

The `definition_template_chash` is computed as `objectHash.getChash160(arrAddressDefinitionTemplate)` over the (variable-templated, non-secret) address-definition template, and is transmitted to every prospective co-signer device via the `create_new_shared_address` message during setup. Consequently, *any* device that is a correspondent of the initiator and legitimately or illegitimately learns/derives this chash (including any device that itself was invited to be one member of a different signing path, or an indirect correspondent for pairing/xpubkey-only whitelisted subjects) can forge a `reject_new_shared_address` message and destroy the pending multi-party (multisig) shared-address negotiation before it completes — with zero check that the sender is a party to that specific address.

### Impact Explanation
This is a caller-side integrity/availability issue on wallet-level shared-address (multisig) setup: an unauthorized paired device can unilaterally abort another party's in-progress shared-address (multisig custody) creation, deleting the associated `pending_shared_address_signing_paths` rows (which include the collected `device_addresses_by_relative_signing_paths` and `approval_date` state contributed by other honest co-signers). This causes the honest participants to lose partially collected approval state for a shared address that may be intended to custody funds, forcing them to restart the address-creation flow — a denial-of-service / freezing of the wallet-setup pipeline for a multi-sig fund address. It does not directly cause double-spend or move already-confirmed on-chain funds, so the reachable outcome is limited to loss/freezing of the shared-address setup process rather than direct theft of already-deposited funds.

### Likelihood Explanation
Reachability requires the attacker to be a paired/correspondent device of one of the parties negotiating the shared address (a low bar, since ocore explicitly allows unsolicited "hub/message" traffic from unknown correspondents for a small whitelist of subjects, and any once-paired device qualifies generally), and to know or guess the `definition_template_chash`, which is exchanged in the clear as part of the `create_new_shared_address` protocol. Because this value is not a secret and the reject handler performs no ownership check, an attacker who intercepts/receives this value (e.g., a malicious cosigner among several designated candidate members) can trivially construct and send the reject message at any time.

### Recommendation
Before calling `deletePendingSharedAddress`, verify that `from_address` is present as a `device_address` in `pending_shared_address_signing_paths` for the given `definition_template_chash` (mirroring the scoping already used in `approvePendingSharedAddress`'s `UPDATE ... WHERE definition_template_chash=? AND device_address=?`), and only proceed with deletion if the sender is one of the genuine invited members.

### Proof of Concept
1. Device A initiates a 2-of-2 shared address with Device B via `createNewSharedAddressByTemplate`, which computes `address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate)` and sends `create_new_shared_address` (containing the template, from which the chash can be recomputed) to Device B [3](#0-2) .
2. Device C, an unrelated but paired correspondent of Device A who obtains/derives the same `address_definition_template_chash` (e.g., by observing the definition template or via any device that received it), sends a `reject_new_shared_address` message with `{address_definition_template_chash}` to Device A.
3. `handleMessageFromHub` on Device A validates only that the value looks like an address and immediately calls `walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash)` [1](#0-0) , deleting the pending shared address and all collected signing-path approvals [4](#0-3) , without ever checking that Device C was one of the addresses in `assocMemberDeviceAddressesBySigningPaths` for this specific shared address.
4. Device A and Device B's in-progress multisig address negotiation is destroyed by a party who was never a member of it.

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

**File:** wallet_defined_by_addresses.js (L106-145)
```javascript
function createNewSharedAddressByTemplate(arrAddressDefinitionTemplate, my_address, assocMyDeviceAddressesByRelativeSigningPaths){
	validateAddressDefinitionTemplate(arrAddressDefinitionTemplate, device.getMyDeviceAddress(), function(err, assocMemberDeviceAddressesBySigningPaths){
		if(err) {
			throw Error(err);
		}

		// assocMemberDeviceAddressesBySigningPaths are keyed by paths from root to member addresses (not all the way to signing keys)
		var arrMemberSigningPaths = Object.keys(assocMemberDeviceAddressesBySigningPaths);
		var address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate);
		db.query(
			"INSERT INTO pending_shared_addresses (definition_template_chash, definition_template) VALUES(?,?)", 
			[address_definition_template_chash, JSON.stringify(arrAddressDefinitionTemplate)],
			function(){
				async.eachSeries(
					arrMemberSigningPaths, 
					function(signing_path, cb){
						var device_address = assocMemberDeviceAddressesBySigningPaths[signing_path];
						var fields = "definition_template_chash, device_address, signing_path";
						var values = "?,?,?";
						var arrParams = [address_definition_template_chash, device_address, signing_path];
						if (device_address === device.getMyDeviceAddress()){
							fields += ", address, device_addresses_by_relative_signing_paths, approval_date";
							values += ",?,?,"+db.getNow();
							arrParams.push(my_address, JSON.stringify(assocMyDeviceAddressesByRelativeSigningPaths));
						}
						db.query("INSERT INTO pending_shared_address_signing_paths ("+fields+") VALUES("+values+")", arrParams, function(){
							cb();
						});
					},
					function(){
						var arrMemberDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
						arrMemberDeviceAddresses.forEach(function(device_address){
							if (device_address !== device.getMyDeviceAddress())
								sendOfferToCreateNewSharedAddress(device_address, arrAddressDefinitionTemplate);
						})
					}
				);
			}
		);
	});
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
