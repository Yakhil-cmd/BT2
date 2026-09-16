## Analysis

The Ella Core bug (GHSA-qfxw-v8qx-vj3v) is a missing authorization/binding check: a message that names a target UE (via `AMF-UE-NGAP-ID`) is trusted without verifying that the sender is actually the entity entitled to act on that target's session. The core defect is "identity is authenticated, but authorization to act on the referenced target is not checked."

There is a directly analogous pattern in ocore's wallet device-message handler, in the `"sign"` request handler's `ifLocal` branch.

### Root cause [1](#0-0) 

In `handleMessageFromHub` → case `"sign"` (`wallet.js`), when a peer device sends a `sign` request naming `body.address` and `body.signing_path`, `findAddress()` resolves whether that address/path is local to this device. If it is (`ifLocal`), the code is supposed to verify that the requesting device (`from_address`, which *is* cryptographically authenticated as the real sender via the device-message ECDSA signature check in `device.js` `handleJustsaying` `hub/message`) is actually a legitimate cosigner of that specific address before proceeding: [2](#0-1) 

```js
ifLocal: function(objAddress){
    // the commented check would make multilateral signing impossible
    //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
    //    if (sender_rows.length !== 1)
    //        return callbacks.ifError("sender is not cosigner of this address");
        callbacks.ifOk();
```

That authorization check is commented out. `from_address` is cryptographically bound to the real sending device (good — this is the equivalent of "the NG Setup / SCTP association is valid"), but there is **no check that this specific correspondent device is entitled to request signing for the specific `body.address`/`body.signing_path` it named** — the equivalent of "does this AMF-UE-NGAP-ID actually belong to a UE served through this radio's association." Any paired correspondent (not just an actual cosigner of a shared/multisig address) can send a `"sign"` message naming any of the victim's own solo or shared addresses along with an attacker-crafted `unsigned_unit`, and the wallet will validate it and fire a `"signing_request"` event that drives the UI's signing confirmation flow using the victim's own key, for a transaction the attacker fully controls (outputs, amounts, asset).

Contrast this with the `ifRemote` branch a few lines below, which does correctly enforce the binding: [3](#0-2) 

```js
ifRemote: function(device_address, other_device_addresses){
    if (device_address === from_address)
        return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
    if (!other_device_addresses.includes(from_address))
        return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```

The `ifLocal` branch lacks the analogous "you are not a cosigner" check that was deliberately disabled.

### Title
Missing Sender-Authorization Binding in Wallet `"sign"` Request Handling Allows Any Correspondent to Initiate Signing Requests for Addresses They Do Not Co-Sign - (File: `wallet.js`)

### Summary
`handleMessageFromHub`'s `"sign"` case in `wallet.js` authenticates the *sender device* (via ECDSA signature verification performed earlier in `device.js`) but never checks whether that sender is actually a legitimate cosigner of the address it names in the request. The check that would enforce this binding is explicitly commented out, letting any paired correspondent device drive a spend-signing confirmation flow for a victim's address using attacker-controlled transaction content.

### Finding Description
`device.js`'s `handleJustsaying` (`hub/message`) cryptographically verifies that a device message really originates from the claimed device (`objDeviceMessage.pubkey` → `ecdsaSig.verify`, and `from_address` cross-checked against the encrypted `json.from`). This establishes sender authenticity, analogous to verifying a radio's NG Setup / SCTP association is valid. [4](#0-3) 

However, once inside `wallet.js`'s `"sign"` handler, the code resolves `body.address` via `findAddress`, and for the `ifLocal` result path (meaning this device controls the signing key for that path), the authorization check binding the *requesting device* to the *specific address it is requesting signing for* has been removed: [5](#0-4) [1](#0-0) 

The rest of the validation in this handler thoroughly checks the *shape* of `unsigned_unit`, private payload hashes, output/input structure, etc., but none of that validates *who is allowed to ask for this address to be signed*. As a result, the sender-authorization binding present in the sibling `ifRemote` branch (`other_device_addresses.includes(from_address)`) is absent from `ifLocal`.

### Impact Explanation
Any device paired as a correspondent (a normal, low-privilege relationship established via `handlePairingMessage`, not a wallet cosigner) can send a `"sign"` message naming any address that is genuinely controlled locally by the victim device (a solo wallet address or a locally-held key inside a shared address) together with an attacker-fabricated `unsigned_unit` whose payment outputs send funds to addresses of the attacker's choosing. Because the cosigner-binding check is disabled, the wallet processes the request as legitimate and raises the `"signing_request"` UI event with the victim's real address and the attacker's crafted spend, using the same code path a genuine cosigner would use. This can result in the user being led to sign and broadcast a transaction whose recipients/amounts were dictated entirely by an unauthorized peer — a direct precursor to unauthorized spending of the victim's funds, analogous to how the Ella Core flaw let an unauthenticated party redirect a legitimate UE's traffic because the target/identity binding was never verified.

### Likelihood Explanation
Any existing chat/pairing correspondent (a peer that only needs to be paired, e.g. via a pairing link, not a cosigner) can trigger this: it only requires knowledge of one of the victim's addresses (which is often shared during payment requests) and sending a single `"sign"` device message. No cosigner relationship or multisig setup is required to reach the vulnerable branch, which the code comment itself acknowledges was deliberately weakened ("the commented check would make multilateral signing impossible").

### Recommendation
Restore and adapt the binding check in the `ifLocal` branch so it still supports legitimate multilateral/multisig signing (where an unrelated cosigner device address is allowed to request a shared address be signed) but rejects requests from devices that have no cosigning/wallet relationship whatsoever with `body.address`. At minimum, verify that `from_address` corresponds to a device_address listed in `wallet_signing_paths`/`shared_address_signing_paths`/`peer_addresses` for that specific address before emitting `"signing_request"`.

### Proof of Concept
1. Attacker device pairs with the victim (normal pairing flow via `device.handlePairingMessage`) so it becomes an ordinary correspondent — no cosigner relationship is created.
2. Attacker learns one of the victim's addresses `A` (a solo `my_addresses` entry, commonly shared during payment requests).
3. Attacker sends a device message: `{subject: "sign", body: {address: A, signing_path: "r", unsigned_unit: <attacker-crafted unit with payment outputs to attacker address>}}`.
4. `wallet.js` `handleMessageFromHub` → case `"sign"` → `findAddress(A, "r", ...)` resolves `ifLocal` since `A` is locally controlled.
5. Because the cosigner check is commented out, `callbacks.ifOk()` fires and `eventBus.emit("signing_request", ...)` is raised with the attacker's transaction content, presenting the victim a confirmation dialog to sign a spend they never initiated, sourced entirely from an unauthorized, non-cosigning peer.

### Citations

**File:** wallet.js (L251-277)
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
```

**File:** wallet.js (L332-372)
```javascript
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```

**File:** device.js (L163-189)
```javascript
			try {
				const bOldHashIsCorrect = (message_hash === objectHash.getBase64Hash(objDeviceMessage));
				if (!bOldHashIsCorrect && message_hash !== objectHash.getBase64Hash(objDeviceMessage, true))
					return network.sendError(ws, "wrong hash");
				if (!ecdsaSig.verify(objectHash.getDeviceMessageHashToSign(objDeviceMessage), objDeviceMessage.signature, objDeviceMessage.pubkey))
					return respondWithError("wrong message signature");
			}
			catch(e){
				return respondWithError("failed to caculate message hash to sign:" + e);
			}
			// end of checks on the open (unencrypted) part of the message. These checks should've been made by the hub before accepting the message
			
			// decrypt the message
			try {
				var json = decryptPackage(objDeviceMessage.encrypted_package);
			}
			catch(e){
				return respondWithError("failed to decrypt: " + e);
			}
			if (!json)
				return respondWithError("failed to decrypt");
			
			// who is the sender
			var from_address = objectHash.getDeviceAddress(objDeviceMessage.pubkey);
			// the hub couldn't mess with json.from as it was encrypted, but it could replace the objDeviceMessage.pubkey and re-sign. It'll be caught here
			if (from_address !== json.from) 
				return respondWithError("wrong message signature");
```
