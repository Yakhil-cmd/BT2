## Title
Missing cosigner-membership check on local "sign" device-message path allows any paired device to trigger unauthorized signing requests - (File: wallet.js)

### Summary
The reported CVE describes a client that holds only a limited (read) permission successfully invoking a privileged action (provider registration) because the specific API entry point never re-validates the caller's authorization, even though the value it registers is later trusted by other clients. The same *"parallel code path has the check, but this one doesn't"* pattern exists in ocore's device-message handler for the `"sign"` subject in `wallet.js`.

### Finding Description
`handleMessageFromHub()` processes the `"sign"` device message that one paired device sends to another to request a signature over a to-be-posted unit (used for multisig/shared-address cosigning) [1](#0-0) . After basic structural checks, it calls `findAddress(body.address, body.signing_path, ...)` and branches on whether the address is local, remote, merkle, or unknown [2](#0-1) .

In the `ifRemote` branch, the code explicitly verifies that the message sender is actually one of the registered cosigner devices for that address before forwarding/proxying the signing offer:
```
ifRemote: function(device_address, other_device_addresses){
    if (device_address === from_address)
        return callbacks.ifError("looping signing request ...");
    if (!other_device_addresses.includes(from_address))
        return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
``` [3](#0-2) 

However, in the `ifLocal` branch — which fires when the *recipient itself* hosts a private key for `body.address` (e.g. as one member of a shared/multisig address) — the equivalent membership check is commented out:
```
ifLocal: function(objAddress){
    // the commented check would make multilateral signing impossible
    //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
    //    if (sender_rows.length !== 1)
    //        return callbacks.ifError("sender is not cosigner of this address");
        callbacks.ifOk();
        ...
        eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
``` [4](#0-3) 

The only prerequisites enforced before firing `"signing_request"` are: `body.address` is a syntactically valid address, `body.address` appears among `objUnit.authors`, the payload hashes are self-consistent, and the recipient locally owns a key for `body.address` [5](#0-4) . There is no check that `from_address` (the device that sent this "sign" request) is actually a member/cosigner (e.g. present in `extended_pubkeys` or in the address's `signers` for shared addresses) of the target address, unlike the symmetric `ifRemote` path.

Any device that is merely a paired correspondent (or, per `handlePairingMessage`, any device that knows a valid/permanent pairing secret and can pair itself) can therefore address a "sign" request at any local address the victim happens to control, supplying an attacker-crafted `unsigned_unit` with outputs directed anywhere, and get the wallet to raise a `"signing_request"` event — the same event a legitimate cosigner flow uses — for a completely unrelated device and unit content, with the internal authorization gate that exists for the remote-proxy case entirely absent for the local case.

### Impact Explanation
The event handler that reacts to `"signing_request"` normally shows the user a confirmation dialog, but nothing in the protocol code guarantees this; automated/headless wallets that key off `"signing_request"` to auto-approve known multisig flows (a common integration pattern for exchanges/services) can be tricked into signing and broadcasting a payment that redirects the victim's funds, since the library gives the caller no signal that the requesting device was never authorized as a cosigner of that address. This maps to unauthorized spending from a wallet-controlled address, matching the "concrete unauthorized spending" acceptance bar.

### Likelihood Explanation
Requires only that the attacker be an accepted correspondent device of the victim (achievable via a shared pairing secret, a common and low-friction step in the wallet UX), and that the victim's device holds a key participating in some multi-authored (shared/multisig) address — a common configuration for shared wallets and prosaic/arbiter contracts. No control over the hub, network, or victim's private keys is needed.

### Recommendation
Restore (and make it not defeat legitimate multilateral signing) the membership check in the `ifLocal` branch: before emitting `"signing_request"`, verify `from_address` is a recognized cosigner/device for `body.address` (via `extended_pubkeys` for keys-based wallets or the shared-address `signers` table for address-based wallets), mirroring the check already present in the `ifRemote` branch.

### Proof of Concept
1. Attacker device pairs with victim device (via a leaked/expired-but-still-valid or permanent pairing secret handled by `handlePairingMessage`).
2. Victim device is one member of a multisig/shared address `body.address` for which it holds a local private key path.
3. Attacker sends a `"sign"` device message to victim: `{address: body.address, signing_path: "r.0", unsigned_unit: {authors:[{address: body.address}], messages:[{app:'payment', payload:{outputs:[{address: attacker_address, amount: N}], inputs:[...]}}]}}`.
4. `findAddress` resolves `ifLocal` because the victim genuinely owns that path; the missing membership check lets the flow proceed straight to firing `"signing_request"` for a unit the attacker fully authored, even though the attacker is not a listed cosigner for `body.address` and would have been rejected had the address instead resolved via `ifRemote`.

### Citations

**File:** wallet.js (L247-330)
```javascript
			// request to sign a unit created on another device
			// two use cases:
			// 1. multisig: same address hosted on several devices
			// 2. multilateral signing: different addresses signing the same message, such as a (dumb) contract
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

**File:** wallet.js (L331-333)
```javascript
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
```

**File:** wallet.js (L334-372)
```javascript
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
