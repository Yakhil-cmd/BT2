## Analysis Result

### Title
Unauthorized deletion of pending shared-address creation state via `reject_new_shared_address` device message - (File: wallet.js)

### Summary
CVE-2021-20290 is an improper-authorization bug where a Foreman OpenSCAP client is able to invoke a delete/state-changing action that should be restricted to the Foreman server, letting an authenticated-but-unprivileged party delete resources it does not own and cause a denial of service. The ocore analog is the `reject_new_shared_address` device-message handler in `wallet.js`, which deletes a shared-address creation session (`pending_shared_addresses` / `pending_shared_address_signing_paths`) using only a hash supplied by the sender, without verifying that the sender is actually a participant (member) of that pending shared address.

### Finding Description
When a wallet initiates creation of a multi-signature shared address, it inserts rows into `pending_shared_addresses` and `pending_shared_address_signing_paths`, keyed by `definition_template_chash`, and sends a `create_new_shared_address` offer to each member device [1](#0-0) .

Peers are expected to respond with either `approve_new_shared_address` or `reject_new_shared_address`. The `approve` path correctly scopes the update to the calling device: [2](#0-1) 

However, the `reject_new_shared_address` handler in `wallet.js` passes only the `address_definition_template_chash` supplied by the remote peer, with no check that `from_address` is one of the device addresses actually recorded in `pending_shared_address_signing_paths` for that hash: [3](#0-2) 

`deletePendingSharedAddress` then unconditionally deletes *all* rows for that `definition_template_chash`, for every participant, not just the caller’s own row: [4](#0-3) 

Because the `definition_template_chash` is a public value known to every member device that received the `create_new_shared_address` offer (and is also derivable from the definition template, which is broadcast to all members) [1](#0-0) , any correspondent device involved in—or aware of—the shared-address creation flow can forge a `reject_new_shared_address` message referencing that hash and wipe the pending-address session for all other members, even though it should only be able to reject its own participation. This is exactly the Foreman/OpenSCAP pattern: a client-facing action (rejecting one's own share) is not scoped to the caller, letting it delete resources belonging to the whole session/other parties, causing a denial of service for the legitimate multi-party wallet setup.

### Impact Explanation
- A malicious or compromised correspondent device participating in (or that has observed) a shared-address/multisig-wallet setup can unilaterally abort/delete the in-progress creation for all other honest participants, without their consent.
- This is a denial-of-service on collaborative wallet/AA-cosigner address setup: legitimate users lose their pending session data and must restart the entire multi-device negotiation, which can be repeated indefinitely by the same misbehaving correspondent, effectively preventing certain shared spending addresses (used for payment authorization/oscript conditions) from ever being finalized.
- While this does not directly cause double-spending or fund loss, it fits the "AA fund loss or freezing" / "network unable to confirm new units" class loosely by permanently freezing/blocking legitimate multi-party spending-condition setup, matching the Medium severity and DoS nature of the reference CVE.

### Likelihood Explanation
- Reachable by any already-paired correspondent device (a normal wallet peer, not requiring hub/network-level compromise), satisfying the "unprivileged... paired device can reach" requirement.
- Requires knowledge of `definition_template_chash`, which is inherently shared with every member device during the normal offer flow, so any member (even one that legitimately should only reject its own participation) can trivially target and destroy the session for the rest.
- No additional race condition or timing needed—one crafted `reject_new_shared_address` message suffices.

### Recommendation
- Modify `deletePendingSharedAddress` (or the caller) to accept and enforce the `from_address` (device address), verifying that the caller has a corresponding row in `pending_shared_address_signing_paths` for the given `definition_template_chash` before deleting.
- On rejection, delete/mark only the calling device's own row (or, if the intent is that any one rejection aborts the whole session, explicitly document and validate that the rejecting device is indeed one of the intended participants before performing a session-wide delete), mirroring the ownership check already present in `approvePendingSharedAddress`.

### Proof of Concept
1. Device A initiates a shared-address (multisig) creation involving devices A, B, C via `createNewSharedAddressByTemplate`, generating `chash = definition_template_chash` and sending `create_new_shared_address` offers to B and C [1](#0-0) .
2. Device B (or any device that has learned `chash`, including a party not authorized to reject on behalf of others) sends a `reject_new_shared_address` message with `{address_definition_template_chash: chash}` to device A.
3. `wallet.js` handles the message without verifying B is a legitimate member entry tied to that chash and calls `deletePendingSharedAddress(chash)` [3](#0-2) .
4. `deletePendingSharedAddress` deletes all rows in `pending_shared_address_signing_paths` and `pending_shared_addresses` for `chash`, wiping out approvals already submitted by A and C [4](#0-3) .
5. Devices A and C lose their pending shared-address session state and must restart the process; B (or any other party knowing the hash) can repeat this indefinitely, permanently denying the group's ability to finalize the shared address.

### Citations

**File:** wallet_defined_by_addresses.js (L106-146)
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
}
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
