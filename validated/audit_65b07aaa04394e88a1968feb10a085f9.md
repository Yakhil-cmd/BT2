Based on my analysis, I found a genuine IDOR analog in the shared-address negotiation flow, comparable in root-cause to the reported passkey bug: a network-facing handler trusts an attacker-controlled ID (`address_definition_template_chash`) to perform a deletion without verifying that the sender is actually a party to that record.

### Title
Unauthorized deletion of pending shared-address negotiation via `reject_new_shared_address` IDOR - (File: wallet_defined_by_addresses.js)

### Summary
The `reject_new_shared_address` device-message handler deletes a pending multi-signature shared-address negotiation identified solely by an attacker-supplied `address_definition_template_chash`, without verifying that the sending device is actually one of the parties participating in that specific pending shared address.

### Finding Description
In `wallet.js`, the `case "reject_new_shared_address"` handler only validates that `body.address_definition_template_chash` is a syntactically valid address/hash, then immediately calls `walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash)` [1](#0-0)  — note that unlike the sibling handler `approve_new_shared_address`, which passes `from_address` into `approvePendingSharedAddress` and that function scopes its `UPDATE` with `AND device_address=?` [2](#0-1) , the reject path passes no `from_address` at all.

`deletePendingSharedAddress` then unconditionally deletes all rows in `pending_shared_address_signing_paths` and `pending_shared_addresses` matching that chash, with no ownership/membership check whatsoever: [3](#0-2) 

This is the same bug class as the reported advisory: an implicitly trusted, attacker-supplied identifier (`ctx.body.id` in the advisory, `address_definition_template_chash` here) is used directly in a delete query with no server-side check that the caller is authorized to act on that specific resource. Any paired correspondent device that learns or is otherwise able to submit a `reject_new_shared_address` message with a given chash can wipe out that pending shared-address negotiation for every other legitimate cosigner, even if the sender was never one of the members listed in `pending_shared_address_signing_paths` for that chash. Contrast this with `handleOfferToCreateNewWallet`'s deletion path (`deleteWallet`), which correctly checks `SELECT approval_date FROM extended_pubkeys WHERE wallet=? AND device_address=?` before allowing a rejection to proceed [4](#0-3) ; the shared-address code path has no analogous check.

### Impact Explanation
This directly disrupts the setup of multi-signature shared addresses used for AA/contract cosigning and multi-device wallets. An unauthorized correspondent (or any device that observes/relays the chash, e.g., an indirect correspondent added via `addIndirectCorrespondents` [5](#0-4) ) can repeatedly delete in-progress negotiations, preventing the legitimate members from ever completing creation of the shared address, which can permanently block funds destined for that address from ever becoming spendable/controllable in the way the users intended (freezing/blocking of a multi-sig arrangement they are relying on).

### Likelihood Explanation
Reaching this handler requires only being a paired correspondent (including an unconfirmed/indirect one is filtered by the earlier correspondent check in `handleJustsaying`'s `hub/message`, which allows `pairing` from unknown senders but requires known correspondents otherwise) and knowledge of the `address_definition_template_chash` value, which is disclosed to all devices sent the `create_new_shared_address` offer during template validation [6](#0-5) . Any of these template recipients — even ones who are not ultimately validated as legitimate signers for a particular negotiation instance — can trigger the deletion, since `deletePendingSharedAddress` performs no membership check.

### Recommendation
Modify the `reject_new_shared_address` handling to pass `from_address` through to `deletePendingSharedAddress`, and change the deletion query to require `AND device_address=?` (mirroring the pattern already used in `approvePendingSharedAddress`), only deleting the signing-path row(s) belonging to the rejecting device, and only removing the parent `pending_shared_addresses` entry once no member rows with pending approval remain or all remaining members have rejected.

### Proof of Concept
1. Device A initiates a shared-address (multisig) setup and sends `create_new_shared_address` template offers to Devices B and C, who both learn `address_definition_template_chash = X`.
2. Device C (or an indirect correspondent that intercepts/knows `X`) sends `{subject: "reject_new_shared_address", body: {address_definition_template_chash: X}}` to Device A, even though Device C has not yet approved.
3. Device A's `wallet.js` handler validates only the shape of `X` and calls `deletePendingSharedAddress(X)`, which deletes `pending_shared_addresses` and all `pending_shared_address_signing_paths` rows for `X` — including Device B's already-recorded approval — with no check that the sender is entitled to cancel that specific negotiation for other members.
4. Device B's prior approval work is silently discarded and the shared-address setup must be restarted, at the sole discretion of any party who can transmit that message, not just an authorized decliner.

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

**File:** wallet_defined_by_addresses.js (L150-154)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
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

**File:** device.js (L906-920)
```javascript
function addIndirectCorrespondents(arrOtherCosigners, onDone){
	async.eachSeries(arrOtherCosigners, function(correspondent, cb){
		if (correspondent.device_address === my_device_address)
			return cb();
		if (!ValidationUtils.isNonemptyString(correspondent.hub) || !network.isValidWsUrl(conf.WS_PROTOCOL + correspondent.hub))
			return cb(); // ignore silently and continue eachSeries
		db.query(
			"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, hub, name, pubkey, is_indirect) VALUES(?,?,?,?,1)", 
			[correspondent.device_address, correspondent.hub, correspondent.name, correspondent.pubkey],
			function(){
				cb();
			}
		);
	}, onDone);
}
```
