Found a concrete missing-authorization analog in the paired-device "sign" handler: the check that verifies whether the requesting device is actually a cosigner of the local (single-signature, non-shared) address before disclosing signing material is deliberately commented out.

### Title
Missing Authorization: any paired device can trigger signing/private-data disclosure for a local address without being a verified cosigner - (File: `wallet.js`)

### Summary
`handleMessageFromHub`'s `"sign"` case calls `findAddress(...)` and, in the `ifLocal` branch (address whose signing key lives on this device), the authorization check that confirms the sender is actually registered as a cosigner of that wallet/address is commented out.

### Finding Description
When a paired device sends a `sign` message requesting this node to sign a unit at a given `address`/`signing_path`, `findAddress` resolves whether the key is local. In the `ifLocal` callback the intended check:
```js
//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
//    if (sender_rows.length !== 1)
//        return callbacks.ifError("sender is not cosigner of this address");
```
is commented out [1](#0-0) , so `callbacks.ifOk()` is called and the `signing_request` event (which drives the confirmation-dialog / signing UI) is emitted for *any* paired device, not only devices actually enrolled as cosigners for that address/wallet (`extended_pubkeys`/`wallet_signing_paths`). The only earlier check performed is that `body.address` is a valid address and appears among `objUnit.authors` [2](#0-1) ; there is no verification that `from_address` (the actual sender, derived from `device_pubkey`) is entitled to request a signature for this address at all — unlike the `ifRemote` branch, which does check `other_device_addresses.includes(from_address)` before proxying [3](#0-2) .

This mirrors the Jenkins Blue Ocean pattern: a code path that should gate on a specific authorization relationship (cosigner membership) instead silently falls back to a weaker check (mere "paired device" / "address referenced in a unit"), analogous to Blue Ocean falling back to `Item/Read` instead of enforcing `Run/Artifacts`.

Additionally, this `sign` message also carries `private_payloads` (`assocPrivatePayloads`) for private-asset payments, which get forwarded via `eventBus.emit("signing_request", ..., assocPrivatePayloads, from_address, ...)` [4](#0-3)  — so an unauthorized paired device can also cause private payment details to be surfaced to the wallet's confirmation flow.

### Impact Explanation
Any device that has ever been paired with the victim's wallet (not necessarily a legitimate cosigner of the specific address in question) can send unsolicited `sign` requests for locally-hosted addresses. Because the cosigner-membership check is disabled, the request is accepted and a `signing_request` event/confirmation dialog is triggered for a unit the attacker fully controls (`body.unsigned_unit`), potentially tricking the user into approving/signing spends or leaking information about which addresses/wallets the recipient controls (an unpaired-cosigner enumeration/oracle). Combined with the multilateral-signing use case explicitly called out in the comment, an unrelated paired device (e.g., from an unrelated "dumb contract") can pull a victim into a signing flow for an address it has no legitimate business co-signing, undermining the authorization model for multisig/multilateral-signing addresses. This does not directly forge a valid signature (the user's approval is still needed), but it removes the intended access-control boundary at the protocol layer, enabling spoofed signing requests and confirmation-dialog spam/social-engineering targeting wallet funds.

### Likelihood Explanation
Reachable by any device paired with the victim (a very weak precondition — "paired device", not "authorized cosigner"), requiring only a correctly-shaped `sign` message referencing a real local address and a syntactically valid unit; no additional privilege is needed since the disabled check is the only gate that would have enforced cosigner membership.

### Recommendation
Re-enable and correctly implement the cosigner-membership check before calling `callbacks.ifOk()`/emitting `signing_request` in the `ifLocal` branch of the `sign` handler — verify `from_address` is a registered device for the wallet (`extended_pubkeys`/`wallet_signing_paths`) associated with `body.address`'s signing path, mirroring the check already present in the `ifRemote` branch (`other_device_addresses.includes(from_address)`).

### Proof of Concept
1. Pair an attacker device with the victim wallet (any legitimate pairing, e.g. via a contract offer or simple pairing flow).
2. Attacker sends a `handleMessageFromHub` message with `subject: "sign"`, `body.address` set to one of the victim's known local addresses (obtainable e.g. from a previous cooperative transaction) and `body.signing_path` `"r"`, plus a crafted `body.unsigned_unit` whose `authors[0].address === body.address`.
3. Because the cosigner check at [5](#0-4)  is commented out, the victim's node accepts the request (`callbacks.ifOk()`) and fires `signing_request`, surfacing a confirmation dialog to the victim for a unit the attacker fully controls, despite the attacker never having been registered as a cosigner for that address.

### Citations

**File:** wallet.js (L253-273)
```javascript
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
```

**File:** wallet.js (L278-348)
```javascript
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
