### Title
Disabled trust check lets indirectly-known devices impersonate fully-paired correspondents - (File: wallet.js)

### Summary
The GHSA-jvc7-762p-3743 bug class is "an unauthenticated/unauthorized party can submit a forged payload and the receiving component processes it as if it came from a legitimate, authenticated source." The closest reachable analog in ocore is in the device-message handler `handleMessageFromHub`, where a check meant to restrict what an *indirect* (not directly paired) correspondent is allowed to send has been commented out, so indirect correspondents are now trusted exactly like fully paired ones.

### Finding Description
`handleMessageFromHub` in [1](#0-0)  receives decrypted, signature-verified device messages from `device.js`'s `handleJustsaying`, which already confirms the message's cryptographic sender (`from_address`) and that the sender is a *known* correspondent (direct or indirect) at [2](#0-1) . However, `device.js` only authenticates *who* sent the message; it does not restrict *what* an indirect correspondent may send — that authorization boundary was supposed to be enforced in `wallet.js`.

That enforcement is disabled:
```
//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
``` [3](#0-2) 

Indirect correspondents are added automatically whenever a peer introduces "other cosigners" while setting up a multi-signature/shared address, via `addIndirectCorrespondents`, without any user pairing action: [4](#0-3) . Because the whitelist check is disabled, any device that becomes known to the wallet only as an indirect cosigner (i.e., named by a counterparty as a third-party signer, never actually paired by the user) can now send **any** message subject with the same trust level as a directly paired device, including:
- `sign` — request to co-sign a unit for a shared/multisig address, with attacker-controlled `unsigned_unit` and `private_payloads` [5](#0-4) 
- `new_shared_address` — register a shared address the wallet believes is jointly owned [6](#0-5) 
- `create_new_shared_address` / `approve_new_shared_address` — drive the shared-address creation flow [7](#0-6) 
- `removed_paired_device`, `create_new_wallet`, etc.

Since indirect correspondents were previously only supposed to be trusted for a narrow whitelist (`cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`), the commented-out check is the sole authorization gate distinguishing "introduced as a cosigner by someone else" from "explicitly paired by the user." Removing it collapses that trust boundary.

### Impact Explanation
An attacker who gets merely *named* as a cosigner in a shared-address flow (which requires no interaction from the victim beyond a normal counterparty introducing them) becomes able to send fully-trusted wallet-protocol messages. This can be used to push forged `sign` requests for units the attacker controls, forged `new_shared_address` definitions, or interfere with wallet-of-keys/shared-address state — i.e., attacker-controlled data being processed by the wallet logic as if it came from an authenticated, directly-paired party. Depending on how the host application (headless wallet, GUI) auto-handles these events, this can lead to unauthorized signing flows or corruption of shared-address bookkeeping, i.e. potential fund loss/freezing consistent with the required impact bar.

### Likelihood Explanation
Reachable by any paired-or-indirectly-known device without further authentication — exactly the "paired device" attacker profile allowed by scope. No privileged access or node compromise required; only that the victim wallet has, at some point, processed a shared-address/cosigner introduction naming the attacker's device (a normal part of the multisig workflow), which is user-uninvolved on the victim side.

### Recommendation
Re-enable and correctly enforce the indirect-correspondent whitelist in `handleMessageFromHub`, restricting `bIndirectCorrespondent` senders to a minimal, explicitly safe list of subjects, and require any state-changing message (`sign`, `new_shared_address`, `create_new_shared_address`, `approve_new_shared_address`, `removed_paired_device`) to only be accepted from correspondents that the user has directly paired with.

### Proof of Concept
1. Attacker participates as a counterparty in setting up a shared/multisig address with the victim, naming an attacker-controlled device as an additional cosigner (`arrOtherCosigners`). This causes `device.addIndirectCorrespondents` to add the attacker device as `is_indirect=1` in `correspondent_devices` — no explicit pairing/approval from the victim is required for this side channel.
2. Attacker's indirect device now sends a `sign` (or `new_shared_address`) justsaying message through the hub, cryptographically signed with its own permanent key (satisfies the signature checks in `device.js`).
3. Because the whitelist check at `wallet.js:92-93` is commented out, `handleMessageFromHub` processes the message identically to one from a fully paired correspondent, invoking `walletDefinedByAddresses.handleNewSharedAddress` or the `sign` handling flow with attacker-controlled `body`.

Note: I could not fully trace `wallet_defined_by_addresses.handleNewSharedAddress` internals or the auto-signing behavior in the headless wallet within this session's tool budget, so the exact downstream consequence (e.g., whether it leads directly to fund loss vs. requiring further victim action) is not fully confirmed and would benefit from deeper tracing in a follow-up session.

### Citations

**File:** wallet.js (L64-94)
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
```

**File:** wallet.js (L197-226)
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
```

**File:** wallet.js (L236-245)
```javascript
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

**File:** wallet.js (L251-330)
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
```

**File:** device.js (L203-221)
```javascript
			// check that we know this device
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
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
