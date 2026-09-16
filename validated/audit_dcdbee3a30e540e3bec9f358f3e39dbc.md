### Title
Disabled Indirect-Correspondent Authorization Check in `handleMessageFromHub` Allows Untrusted Devices to Trigger Privileged Wallet Operations - (File: wallet.js)

### Summary
`wallet.js`'s `handleMessageFromHub()` is the single entry point that dispatches every incoming device-chat message (`subject`/`body`) to wallet logic based on the `from_address` derived from the sender's device pubkey [1](#0-0) . The function receives a `bIndirectCorrespondent` flag meant to distinguish directly-paired, trusted correspondents from correspondents reached only indirectly (e.g., introduced through another correspondent, not verified through a full pairing handshake). The code that was supposed to restrict indirect correspondents to a narrow safe allow-list of subjects is commented out, so **every** subject — including privileged, fund-affecting ones such as `sign`, `create_new_shared_address`, `new_shared_address`, `create_new_wallet`, and `removed_paired_device` — is now dispatched identically regardless of trust level. This is the same class of bug as the Lyra report: an authorization gate meant to separate a low-trust caller from a high-trust caller was collapsed/disabled, silently expanding the set of principals that can invoke sensitive operations.

### Finding Description
`handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks)` is called for messages relayed by the hub to a wallet/device. Just like `LyraPositionHandlerL2.onlyAuthorized`, which merges two structurally different sender classes (`keeper` and `L2CrossDomainMessenger`) under one check and then reuses that check for functions that should require a stricter, narrower set of callers, ocore's dispatcher merges "directly paired correspondent" and "indirect correspondent" under one code path via the disabled guard: [2](#0-1) 

The intended design (visible from the comment) was: if `bIndirectCorrespondent` is true, only `cancel_new_wallet`, `my_xpubkey`, and `new_wallet_address` should be accepted — everything else should be rejected with `"you're indirect correspondent, cannot trust ... from you"`. With this check disabled, the full `switch(subject)` dispatch table below is reachable by an indirect correspondent, including:

- `create_new_wallet` — initiates creation of a multi-signature wallet with attacker-supplied `wallet_definition_template` and `other_cosigners` [3](#0-2) 
- `create_new_shared_address` / `approve_new_shared_address` / `new_shared_address` — creates/announces a shared (co-signed) address whose definition and signer map come from the message body [4](#0-3) 
- `sign` — requests the wallet to sign or relay a signing request for an arbitrary unit, including proxying as `ifRemote` to another cosigner device [5](#0-4) 
- `removed_paired_device` — can trigger removal of a legitimate correspondent, causing denial of communication with real cosigners [6](#0-5) 

None of these subjects perform any additional check that the sender is a verified, directly-paired correspondent; the address-level checks inside (e.g., `findAddress`, `ifLocal`/`ifRemote`/`ifUnknownAddress` in the `sign` handler) only verify that the *address* argument is known/local — they do not re-verify the *correspondent's trust tier*, because that check was supposed to happen earlier in the dispatcher and was disabled.

### Impact Explanation
This breaks the same invariant the Lyra report flags: a modifier/gate intended to separate a narrow, high-trust caller set from a broader, low-trust caller set is missing on functions that have fund-relevant consequences. Concretely:
- A device that is only indirectly known to the wallet (never fully paired/verified) can initiate multi-sig wallet creation or shared-address flows that end up presenting the user with UI dialogs (`create_new_wallet`, `create_new_shared_address` events) impersonating a legitimate cosigner, potentially leading the user to co-sign/fund an address that is not what they believe it is.
- An indirect correspondent can inject `sign` requests, causing the wallet to display attacker-crafted units in the signing UI and, in the `ifRemote` case, proxy the request onward to a genuine cosigner device — increasing the attack surface for social-engineering the user into authorizing an unintended payment (unauthorized spending / fund loss), matching the "concrete unauthorized spending... AA fund loss" acceptance criteria.
- `removed_paired_device` can be abused to sever legitimate multisig cosigner relationships, freezing the ability to complete pending co-signed payments (fund freezing / DoS on the wallet's spending capability).

### Likelihood Explanation
The guard is not merely under-specified — it is present in the source as a fully-formed check and literally commented out, meaning the vulnerable state is the *current, shipped* behavior rather than a hypothetical omission. Any device that the wallet's hub/correspondent graph classifies as "indirect" (a normal, expected category in the pairing protocol, not requiring a malicious hub or network-level attack) can reach the full message-subject dispatch table with a single device chat message, satisfying the "single … paired device can reach" reachability bar from an ordinary wallet-protocol interaction.

### Recommendation
Re-enable and enforce the allow-list check for `bIndirectCorrespondent` before entering the `switch(subject)` dispatch in `doHandle()`:
```js
if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
```
Additionally, apply defense-in-depth by having the higher-risk handlers (`sign`, `create_new_shared_address`, `new_shared_address`, `removed_paired_device`, `create_new_wallet`) independently verify that `from_address` corresponds to a fully-paired, directly-trusted correspondent (analogous to introducing an `onlyKeeper`/`onlyGovernance`-style split in the Lyra recommendation) rather than relying solely on the single upstream gate.

### Proof of Concept
1. Establish (or become) an "indirect correspondent" of a victim wallet — i.e., a device address known to the wallet only through introduction/relay rather than full mutual pairing (the exact introduction path is handled in `device.js`, which sets `bIndirectCorrespondent`).
2. From that indirect device, send a hub message with `subject: "sign"` and a `body` containing an attacker-crafted `unsigned_unit` referencing one of the victim's real addresses/signing paths.
3. Because the `bIndirectCorrespondent` allow-list check in `wallet.js` is disabled, the message reaches the `case "sign"` handler exactly as if sent by a fully-trusted, directly-paired cosigner, triggering the `signing_request` event/UI flow (or the `ifRemote` proxy path) without any distinction based on trust tier [5](#0-4) .
4. Repeat with `subject: "create_new_shared_address"` or `"new_shared_address"` to demonstrate that shared-address creation/approval flows are equally reachable from the untrusted indirect correspondent [4](#0-3) .

Note: I was unable to inspect the exact logic in `device.js` that computes/sets `bIndirectCorrespondent` (only match counts were available, not file contents) — confirming the precise conditions under which a correspondent becomes "indirect" would require pulling `device.js` in full, e.g., via a Devin session with complete file access.

### Citations

**File:** wallet.js (L64-99)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});

		
	function doHandle() {

		var subject = json.subject;
		var body = json.body;
		if (!subject || typeof body == "undefined" || body === null)
			return callbacks.ifError("no subject or body");
		if (typeof subject !== "string")
			return callbacks.ifError("subject is not a string");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
		switch (subject){
			case "pairing":
				device.handlePairingMessage(json, device_pubkey, callbacks);
				break;
```

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

**File:** wallet.js (L150-153)
```javascript
			case "create_new_wallet":
				// {wallet: "base64", wallet_definition_template: [...]}
				walletDefinedByKeys.handleOfferToCreateNewWallet(body, from_address, callbacks);
				break;
```

**File:** wallet.js (L197-245)
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
				
			case "reject_new_shared_address":
				// {address_definition_template_chash: "BASE32"}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
				callbacks.ifOk();
				break;
				
			case "new_shared_address":
				// {address: "BASE32", definition: [...], signers: {...}}
				walletDefinedByAddresses.handleNewSharedAddress(body, {
					ifError: callbacks.ifError,
					ifOk: function(){
						callbacks.ifOk();
						eventBus.emit('maybe_new_transactions');
					}
				});
				break;
```

**File:** wallet.js (L251-404)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
				var assocPrivatePayloads = body.private_payloads;
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (("messages" in objUnit) + ("signed_message" in objUnit) !== 1)
					return callbacks.ifError("either messages or signed_message must be present, but not both");
				if ("messages" in objUnit){
					const validation = require('./validation.js');
					if (!validation.hasValidPayloadHashes({ unit: objUnit }))
						return callbacks.ifError("invalid payload hashes");
					if (!objUnit.messages.find(m => m.app === 'payment'))
						return callbacks.ifError("no payment messages");
					for (let m of objUnit.messages) {
						if (m.app !== 'payment' || m.payload_location !== 'inline') continue;
						if (!ValidationUtils.isNonemptyArray(m.payload.outputs) || !m.payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isPositiveInteger(o.amount)))
							return callbacks.ifError("invalid payment outputs");
						if (!ValidationUtils.isNonemptyArray(m.payload.inputs) || !m.payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
							return callbacks.ifError("invalid payment inputs");
					}
				}
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
							if (objUnit.signed_message && !ValidationUtils.hasFieldsExcept(objUnit, ["signed_message", "authors", "version"])){
								try {
									objUnit.unit = objectHash.getBase64Hash(objUnit); // exact value doesn't matter, it just needs to be there
								}
								catch (e) {
									console.log("signed message hash failed", e);
									objUnit.unit = "failedunit";
								}
								return eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							}
							try {
								objUnit.unit = objectHash.getUnitHash(objUnit);
							}
							catch (e) {
								console.log("to-be-signed unit hash failed", e);
								return;
							}
							var objJoint = {unit: objUnit, unsigned: true};
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
						//});
					},
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
						try {
							var text_to_sign = objectHash.getUnitHashToSign(body.unsigned_unit).toString("base64");
						}
						catch (e) {
							return callbacks.ifError("unit hash failed: " + e.toString());
						}
						// I'm a proxy, wait for response from the actual signer and forward to the requestor
						eventBus.once("signature-"+device_address+"-"+body.address+"-"+body.signing_path+"-"+text_to_sign, function(sig){
							sendSignature(from_address, text_to_sign, sig, body.signing_path, body.address);
						});
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
						callbacks.ifOk();
					},
					ifMerkle: function(bLocal){
						callbacks.ifError("there is merkle proof at signing path "+body.signing_path);
					},
					ifUnknownAddress: function(){
						callbacks.ifError("not aware of address "+body.address+" but will see if I learn about it later");
						eventBus.once("new_address-"+body.address, function(){
							// rewrite callbacks to avoid duplicate unlocking of mutex
							handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, { ifOk: function(){}, ifError: function(){} });
						});
					}
				});
				break;
```
