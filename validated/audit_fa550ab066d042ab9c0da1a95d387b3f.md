### Title
Missing indirect-correspondent trust check allows unpaired/indirectly-known devices to trigger privileged wallet operations - ([File: wallet.js])

### Summary
`handleMessageFromHub` in `wallet.js` is supposed to restrict which `subject`s an "indirect correspondent" (a device that is only indirectly known, e.g. introduced via a shared-address flow, with `is_indirect=1` in `correspondent_devices`) is allowed to send. The enforcement code is commented out, so any device address that can get a message delivered to the wallet through the hub — including indirectly-known/untrusted devices — can invoke any `subject` handler in the switch statement, not just the intended whitelist (`cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`).

### Finding Description
`handleMessageFromHub` receives `bIndirectCorrespondent` from the hub-message dispatch pipeline (`device.js` `handleJustsaying` case `'hub/message'`, which looks up `is_indirect` from `correspondent_devices` and passes it through `eventBus.emit("handle_message_from_hub", ws, json, objDeviceMessage.pubkey, bIndirectCorrespondent, ...)`), yet the actual gating check on that flag is disabled: [1](#0-0) 

```
//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
```

Because this check is commented out, `subject` dispatch falls straight into the switch statement for every correspondent — direct or indirect — meaning the intended trust boundary (only three "low-risk" subjects for devices you haven't fully vetted/paired with, e.g., devices introduced only via shared-address negotiation) is not enforced. Reachable subjects include `sign` (co-signing requests for shared/multisig addresses), `private_payments` (`handlePrivatePaymentChains`), `create_new_shared_address`/`approve_new_shared_address`, and other wallet-state-changing subjects: [2](#0-1) [3](#0-2) 

The device-address identity used for `from_address` is cryptographically verified at the hub-message layer (`device.js`), and the hub only rejects fully-unknown correspondents for non-whitelisted subjects: [4](#0-3) . This means the class of devices this wallet.js check is meant to further restrict — devices already recorded as correspondents but flagged `is_indirect` (lower trust, e.g., not the user's actively-paired counterpart but discovered through the multi-signer/shared-address introduction flow, see `wallet_defined_by_keys.js`) — get the same access as a fully-paired, directly-trusted device.

This is directly analogous to the Hoppscotch CVE-2024-34714 bug class: a critical allow-list/origin check ("only allow-listed subjects from this class of sender") was present in intent but not actually enforced due to code being effectively disabled, letting a less-trusted sender reach privileged message handlers it was never supposed to reach.

### Impact Explanation
An indirectly-known device (one added as a correspondent only through the introduction/shared-address workflow, not a device the user has explicitly, fully paired and trusted) can send `sign` requests for shared addresses the wallet co-owns, or inject `private_payments`/`payment_notification` messages, or manipulate shared-address negotiation state (`create_new_shared_address`, `approve_new_shared_address`, `new_shared_address`) beyond what the intended trust tier permits. In multisig/shared-address setups this can cause the wallet to display/act on unauthorized co-signing requests or process spurious private payment claims from a device that was never meant to be treated as a fully-trusted correspondent, undermining the isolation the `is_indirect` trust tier was designed to provide and potentially contributing to unauthorized fund movement via multisig cosigning flows or false private-payment state.

### Likelihood Explanation
Any device that ends up in `correspondent_devices` with `is_indirect=1` — which happens through routine flows like shared multisig-address setup — automatically gains this expanded access with no additional user action, since the gating `if` statement is simply commented out rather than conditionally bypassed. No special conditions or race are needed; every message from such a device is dispatched with full subject access.

### Recommendation
Restore and enforce the indirect-correspondent subject whitelist check in `handleMessageFromHub` (`wallet.js` line ~92-93), rejecting any `subject` not in the explicitly-approved low-risk list when `bIndirectCorrespondent` is true, and audit whether the whitelist itself (`cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`) is still appropriate given the current set of subjects (e.g., `sign`, `private_payments`) that must never be trusted from indirect correspondents.

### Proof of Concept
1. Attacker's device becomes an indirect correspondent of the victim wallet by participating in a shared-address definition-template exchange (`create_new_shared_address` flow) so that `correspondent_devices.is_indirect=1` is set for the attacker's device address, per `device.js` correspondent bookkeeping.
2. Attacker sends a `hub/message`-relayed device message with `subject: "sign"` (or `private_payments`) to the victim through the hub, properly signed with the attacker's own device key so it passes `device.js` signature/hash checks.
3. Because the `bIndirectCorrespondent` gate in `wallet.js` (lines 92-93) is commented out, `doHandle()` proceeds directly into the `sign`/`private_payments` case instead of being rejected with "you're indirect correspondent, cannot trust ... from you" — demonstrating the intended trust-tier restriction is not enforced. [5](#0-4)

### Citations

**File:** wallet.js (L90-94)
```javascript
		if (typeof subject !== "string")
			return callbacks.ifError("subject is not a string");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
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

**File:** wallet.js (L406-424)
```javascript
			case "signature":
				// {signed_text: "base64 of sha256", signing_path: "r.1.2.3", signature: "base64"}
				if (!ValidationUtils.isStringOfLength(body.signed_text, constants.HASH_LENGTH)) // base64 of sha256
					return callbacks.ifError("bad signed text");
				if (!ValidationUtils.isStringOfLength(body.signature, constants.SIG_LENGTH) && body.signature !== '[refused]')
					return callbacks.ifError("bad signature length");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("bad address");
				eventBus.emit("signature-" + from_address + "-" + body.address + "-" + body.signing_path + "-" + body.signed_text, body.signature);
				callbacks.ifOk();
				break;
				
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
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
