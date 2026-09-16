Found a concrete analog: the `"removed_paired_device"` handler in `wallet.js` lets a paired correspondent unilaterally delete the local shared/multisig cosigning relationship — with no re-authentication, confirmation prompt, or notification comparable to what Mahara's fix requires for sensitive account changes.

#### Title
Paired device can silently trigger unauthenticated removal of a cosigning correspondent - (File: wallet.js)

#### Summary
CVE-2017-1000141 concerns Mahara allowing sensitive, irreversible account operations (changing username/email, deleting the account) to be processed from a bare request, without prompting for the password or notifying the account owner. The reachable analog in `ocore--012` is the `"removed_paired_device"` message handler, which lets any already-paired device unilaterally remove itself as a correspondent from another user's wallet — a security-relevant configuration change — without any additional authentication, user confirmation dialog, or protection against being invoked at an inconvenient time (e.g., mid-signing of a shared multisig transaction).

#### Finding Description
`handleMessageFromHub` in `wallet.js` processes the `"removed_paired_device"` subject by calling `determineIfDeviceCanBeRemoved` and then immediately `device.removeCorrespondentDevice`, with no confirmation event analogous to `create_new_shared_address`/`create_new_wallet`, which do emit a `eventBus.emit("create_new_wallet", ...)`/`create_new_shared_address` to trigger a UI confirmation dialog before committing state: [1](#0-0) 

Contrast this with other sensitive flows in the same switch statement, such as `create_new_shared_address`, which explicitly funnels the request through a UI confirmation event before any state is persisted: [2](#0-1) 

`removeCorrespondentDevice` is only gated by `determineIfDeviceCanBeRemoved`, which merely checks whether the device is *structurally* referenced by open shared-address / wallet signing paths, not whether removing it is *safe* right now (e.g., mid pending multisig transaction, or whether the user wants to be warned before losing a cosigner relationship): [3](#0-2) 

Because the message is processed as soon as it arrives from a device already listed in `correspondent_devices` (verified only by matching the deterministic device_address to the signing pubkey, per `handleJustsaying`'s `hub/message` case), any paired peer — including one who was legitimately paired for an unrelated shared address or arbiter contract — can send this single justsaying message and immediately sever the cosigning relationship with zero confirmation and zero notification comparable to the "warning to primary email" requirement in the CVE.

#### Impact Explanation
For addresses defined via `wallet_defined_by_addresses.js` (multisig/shared addresses) or arbiter/prosaic contracts, correspondent-device relationships are integral to being able to complete a payment: signing requests are routed to the specific `device_address` recorded for a signing path. Silent removal of a correspondent by that same correspondent (self-initiated "unpair") can leave the victim unable to obtain a cosigner's future participation for reconciliation or dispute flows without any prior warning, potentially freezing funds held in a shared address that depends on responsive correspondence with that device, and it happens without any user-facing confirmation step of the kind other correspondent-affecting operations in the same file receive.

#### Likelihood Explanation
Likelihood is high for anyone already paired as a correspondent (a normal, low-barrier state reached through pairing links) — no additional key compromise or malicious-node capability is required. The action is a single justsaying message (`"removed_paired_device"`), and is processed unconditionally by `determineIfDeviceCanBeRemoved`'s structural check, not a security check.

#### Recommendation
Route `"removed_paired_device"` through the same class of user-confirmation event pattern used elsewhere (e.g., `create_new_shared_address`), rather than calling `device.removeCorrespondentDevice` directly; at minimum, emit a user-visible warning/confirmation event before removal when the device is referenced by shared addresses or open contracts, mirroring the "warn the user" remediation pattern in the referenced CVE.

#### Proof of Concept
1. Pair device B with device A (normal pairing flow).
2. Have device A and B jointly create a shared/multisig address via `create_new_shared_address` / `new_shared_address` (`wallet_defined_by_addresses.js`), so B is recorded in `shared_address_signing_paths`.
3. From device B, send a `hub/message` justsaying with `subject: "removed_paired_device"` to device A's hub.
4. Device A's `wallet.js` `doHandle()` processes this in `case "removed_paired_device"`, calls `determineIfDeviceCanBeRemoved`, finds B "removable" per the structural check, and calls `device.removeCorrespondentDevice(from_address, ...)` — deleting the correspondent with no confirmation dialog shown to A's user and no notice sent to A about why cosigning capability was just lost. [1](#0-0)

### Citations

**File:** wallet.js (L124-142)
```javascript
			case "removed_paired_device":
			//	if(conf.bIgnoreUnpairRequests) {
			//		// unpairing is ignored
			//		callbacks.ifError("removed_paired_device ignored: "+from_address);
			//	} else {
					determineIfDeviceCanBeRemoved(from_address, function(bRemovable){
						if (!bRemovable)
							return callbacks.ifError("device "+from_address+" is not removable");
						if (conf.bIgnoreUnpairRequests){
							db.query("UPDATE correspondent_devices SET is_blackhole=1 WHERE device_address=?", [from_address]);
							return callbacks.ifOk();
						}
						device.removeCorrespondentDevice(from_address, function(){
							eventBus.emit("removed_paired_device", from_address);
							callbacks.ifOk();
						});
					});
			//	}
				break;
```

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
```

**File:** wallet.js (L2990-3022)
```javascript
}

function readNonRemovableDevices(onDone){

	var sql = "SELECT DISTINCT device_address FROM shared_address_signing_paths ";
	sql += "UNION SELECT DISTINCT device_address FROM wallet_signing_paths ";
	sql += "UNION SELECT DISTINCT device_address FROM pending_shared_address_signing_paths ";
	sql += "UNION SELECT DISTINCT peer_device_address AS device_address FROM prosaic_contracts ";
	sql += "UNION SELECT DISTINCT peer_device_address AS device_address FROM wallet_arbiter_contracts ";
	sql += "UNION SELECT DISTINCT arbstore_device_address AS device_address FROM arbiter_disputes ";
	if (conf.ArbStoreWebURI)
		sql += "UNION SELECT DISTINCT device_address AS device_address FROM arbiters";
	
	db.query(
		sql, 
		function(rows){
			
			var arrDeviceAddress = rows.map(function(r) { return r.device_address; });

			onDone(arrDeviceAddress);
		}
	);
}

function determineIfDeviceCanBeRemoved(device_address, handleResult) {
	device.readCorrespondent(device_address, function(correspondent){
		if (!correspondent)
			return handleResult(false);
		readNonRemovableDevices(function(arrDeviceAddresses){
			handleResult(arrDeviceAddresses.indexOf(device_address) === -1);
		});
	});
};
```
