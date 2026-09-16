### Title
Local signing requests are accepted from any paired correspondent device without verifying cosigner authorization - ([File: ocore--013/wallet.js])

### Summary
`wallet.js`'s `handleMessageFromHub` `"sign"` case authenticates the *sender* of a device message (an authenticated device address, from the ECDSA-verified `hub/message` envelope) but does not verify that the sender is actually authorized to request a signature over an address hosted on this device. The check that would enforce this is explicitly commented out, mirroring the flash-loan bug class in the report: the immediate caller's identity is validated, but the caller's *authorization to trigger this specific sensitive action* is not.

### Finding Description
In the device-message dispatcher, incoming messages are authenticated at the transport layer (`device.js` `handleJustsaying`, `hub/message` case) by verifying `objDeviceMessage.signature` against `objDeviceMessage.pubkey` and deriving `from_address = objectHash.getDeviceAddress(pubkey)`: [1](#0-0) 

That authenticates *who* sent the message, but does not establish that the sender is entitled to request the specific action encoded in the message body. In `wallet.js`, the `"sign"` case for `findAddress(...).ifLocal` is reached for any correspondent device that sends a syntactically valid signing request naming one of the local wallet's addresses: [2](#0-1) 

The code that would restrict this to devices that are actually registered cosigners of the target address (`SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?`) is present in the source but deliberately disabled: [3](#0-2) 

The comment explicitly states the check was left out because "the commented check would make multilateral signing impossible" — i.e., the design intentionally trusts any correspondent to submit signing material for a local private key, on the assumption that a human will confirm via the `"signing_request"` event/dialog. Any device that is a correspondent (paired device) of the victim's wallet — not necessarily a cosigner of the target address — can submit an `unsigned_unit` with attacker-chosen `authors`, `messages`/`signed_message` content and drive the local wallet into emitting a `"signing_request"` for arbitrary transaction content, exactly analogous to the flash-loan callback trusting attacker-supplied `params`/`data` because it only checked that the caller was *a* legitimate provider, not *the* legitimate initiator.

### Impact Explanation
If the `"signing_request"` consumer performs any form of automatic/headless signing (as is common for exchange/service wallets built on ocore that don't always show interactive confirmation for every signing path, or that pattern-match on address/path rather than re-verifying the requester is a legitimate cosigner), an attacker who is merely paired as a correspondent — without being a wallet cosigner — can get the wallet to sign attacker-chosen unit content (arbitrary outputs/messages) for shared/multisig addresses hosted on that device. This can lead to unauthorized spending from shared addresses or impersonation of another cosigner's transaction, i.e., concrete unauthorized fund movement.

### Likelihood Explanation
Exploitability requires only that the attacker be a paired device/correspondent of the victim's wallet (a normal, low-privilege relationship achievable via standard pairing flows) and that the victim's wallet process a `"sign"` request without the disabled cosigner check being reinstated. The vulnerable code path is reached automatically upon receipt of any well-formed `sign` message satisfying the field/hash checks; no additional network or hub compromise is needed.

### Recommendation
Reinstate (or replace with an equivalent authorization check) the verification that the sending device is actually a registered cosigner/signing-path holder for `body.address` before accepting a `"sign"` request and emitting `"signing_request"`. If multilateral signing (case 2 in the code comment, "different addresses signing the same message") is required, add a distinct, explicit authorization check for that use case (e.g., verify the requesting device's address is part of the same shared-address/contract context) rather than removing authorization entirely for all signing requests.

### Proof of Concept
1. Device B pairs with Device A as an ordinary correspondent (not added as a cosigner to any of Device A's shared addresses).
2. Device B sends Device A a `"sign"` message: `{address: <A's shared address>, signing_path: "r.1.2.3", unsigned_unit: {authors: [{address: <A's shared address>, authentifiers: {...}}], messages: [...attacker-chosen outputs...]}}`.
3. Because `authorAddresses.includes(body.address)` and payload-hash checks pass, `findAddress` resolves `ifLocal`, and since the cosigner check is commented out, `callbacks.ifOk()` fires and `"signing_request"` is emitted with the attacker's unit content — with no verification that Device B is entitled to request this signature for that address. [2](#0-1) 

**Note:** I could not locate, within this repository's indexed contents, the consumer(s) of the `"signing_request"` event (e.g., a headless/automatic-signing wallet implementation) to confirm whether any such consumer performs unattended signing without re-checking cosigner status; this repo only contains the emitter side (`wallet.js`) and no `eventBus.on("signing_request", ...)` handler was found in the indexed files. If a Devin session with full filesystem access were used, this should be verified in any headless-wallet integrations that consume ocore's `device` event bus, since that determines whether this leads directly to unattended fund loss or only to a spoofed UI confirmation dialog.

### Citations

**File:** device.js (L164-189)
```javascript
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

**File:** wallet.js (L331-349)
```javascript
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
```
