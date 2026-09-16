Found a solid analog. Here's the finding:

### Title
Cross-Device Unauthorized Deletion of Pending Shared Address via Missing Membership Check in `reject_new_shared_address` - (File: wallet.js)

### Summary
The `reject_new_shared_address` device-message handler deletes a pending multi-device shared-address negotiation identified only by its `address_definition_template_chash`, without verifying that the sending device is actually a participant (member) of that specific pending shared address. This mirrors the Gitea bug class: an object (attachment / pending shared address) is deleted based on a caller-supplied identifier, while the authorization check validates only the message type/sender pairing status, not whether the sender is actually bound to that specific object's context (repo / shared-address negotiation).

### Finding Description
In `wallet.js`, the `handleMessageFromHub` switch statement handles the `"reject_new_shared_address"` subject: [1](#0-0) 

This only validates that `body.address_definition_template_chash` is a syntactically valid address/chash, then immediately calls `walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash)` — with no check that `from_address` (the device sending the message) is one of the member devices recorded for that `definition_template_chash`.

`deletePendingSharedAddress` unconditionally deletes both the pending signing paths and the pending shared address record for the given chash: [2](#0-1) 

Contrast this with the sibling handler `cancel_new_wallet` for singlesig/multisig wallets, which correctly verifies membership before deleting: `deleteWallet` first checks `SELECT approval_date FROM extended_pubkeys WHERE wallet=? AND device_address=?` and bails out (`return onDone()`) if the rejecting device is not actually a recorded member of that wallet: [3](#0-2) 

No equivalent `WHERE ... AND device_address=?` membership check exists for `deletePendingSharedAddress`. Any paired (or even non-strictly-verified indirect) correspondent device can send a `reject_new_shared_address` message referencing an `address_definition_template_chash` it can guess or has learned out-of-band (e.g., leaked, observed, or brute-forced since chashes derived from a definition template may be predictable/shared across cosigners), and unilaterally wipe out another user's in-progress shared-address negotiation, even though it is not a party to that address's definition template at all.

### Impact Explanation
An attacker's device (any paired correspondent) can destroy the pending state of a legitimate multi-signature shared-address setup between other unrelated devices, by simply replaying/guessing the `definition_template_chash` value. Because `pending_shared_addresses` and `pending_shared_address_signing_paths` rows are deleted outright (not just marked), the negotiation must restart from scratch. If any counterparty had already begun sending funds to the anticipated shared address (a common workflow where funds are pre-committed while multisig setup finalizes), disrupting/erasing the local approval-tracking state can cause the shared address to never be finalized on the affected node, leading to loss of coordination and potential loss/freezing of funds intended for that shared multisig address on the victim's device.

### Likelihood Explanation
Reachable purely from a paired device sending a crafted `pairing`-level JSON message (`subject: "reject_new_shared_address"`), requiring no special privilege beyond being a correspondent device — matching the "paired device" reachable class allowed by scope. The chash is a public value that may be observable via prior message exchange or through shared/forwarded correspondence, making exploitation practical without needing to compromise the victim.

### Recommendation
Before calling `deletePendingSharedAddress`, verify that `from_address` is actually listed among the member `device_address` values in `pending_shared_address_signing_paths` for the given `definition_template_chash`, mirroring the ownership check already performed in `wallet_defined_by_keys.js`'s `deleteWallet`. Reject the deletion with `callbacks.ifError` if the sender is not a recognized member of that specific pending address.

### Proof of Concept
1. Device A and Device B begin creating a shared address; Device A calls `createNewSharedAddressByTemplate`, inserting a row into `pending_shared_addresses`/`pending_shared_address_signing_paths` keyed by `address_definition_template_chash` [4](#0-3) .
2. Attacker device C, which is merely paired with Device A (unrelated to this negotiation) but has learned or guessed the `address_definition_template_chash` value, sends a hub message: `{subject: "reject_new_shared_address", body: {address_definition_template_chash: "<chash>"}}`.
3. Device A's `handleMessageFromHub` processes this in the `"reject_new_shared_address"` case, only checking chash validity, then calls `deletePendingSharedAddress(chash)` [1](#0-0) .
4. The pending shared address rows are deleted, even though Device C was never one of the address's intended cosigner devices, breaking Device A/B's in-progress multisig setup without their consent.

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

**File:** wallet_defined_by_addresses.js (L230-234)
```javascript
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
