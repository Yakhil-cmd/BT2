### Title
Missing cosigner/authorization check in wallet "sign" request handler allows unrelated paired devices to trigger signing requests for addresses they don't co-own - (File: wallet.js)

### Summary
In `handleMessageFromHub`'s handling of the `"sign"` device message (`wallet.js`), the code path taken when the requested address is locally owned (`ifLocal`) never verifies that the device that sent the signing request is actually a cosigner/member of that address. The equivalent check exists — and is enforced — only in the `ifRemote` branch. This mirrors the Kanboard `getSwimlane` bug class: a resource (here, a wallet address / shared-address signing capability) is looked up and acted upon by identifier alone, without validating that the caller (an authenticated party — a paired device instead of a project member) is actually authorized to access/operate on that specific resource.

### Finding Description
`handleMessageFromHub` processes the `"sign"` subject sent by any known correspondent device (paired device) [1](#0-0) . For the `"sign"` case, `findAddress(body.address, body.signing_path, ...)` resolves whether `body.address` is a personal/local address, a shared-address member path, or belongs to a remote device [2](#0-1) .

When the address resolves as `ifLocal` (i.e., it is really an address controlled by this device, either directly or as leaf of a shared-address tree), the code that would confirm the requesting device (`from_address`) is actually one of the address's cosigners is commented out: [3](#0-2) 
Execution proceeds straight to `callbacks.ifOk()` and emits `"signing_request"`, which drives the wallet UI to display a confirmation prompt to the user, using attacker-supplied `objUnit`/`assocPrivatePayloads` [4](#0-3) .

By contrast, the `ifRemote` branch — used when the resolved signer lives on a different device — does perform the authorization check, rejecting requests unless the sender is explicitly listed as one of the other cosigner devices for the same shared address: [5](#0-4) 

This asymmetry means: for any address that is *locally* held (a personal address, or a shared/multisig address where the local device is the actual signer for the requested path), **any correspondent device that has ever been paired** (not necessarily a member of that specific shared/multisig address definition) can send a crafted `"sign"` message for `body.address` + `body.signing_path` and have it processed as if it were a legitimate cosigner request — reaching the `signing_request` event, the confirmation-dialog UI flow, and `network.handleOnlineJoint` validation of an attacker-supplied unit. It also functions as a cross-resource information oracle: the different callback paths (`ifLocal` vs `ifRemote` vs `ifMerkle` vs `ifUnknownAddress`) leak to any paired device whether a given address belongs to the victim's wallet and what role the victim plays in it, without the victim device ever having shared that address with the attacker's device.

### Impact Explanation
An unrelated paired device (analogous to an "authenticated user without project access" in the Kanboard bug) can:
- Force the wallet UI to surface a signing confirmation dialog for a transaction the attacker constructed (`body.unsigned_unit`), including private payloads (`assocPrivatePayloads`), for any locally-controlled address — even addresses/shared-address paths the attacker was never given access to. If the user is careless (or automation trusts the flow), this can lead to signing/spending funds the attacker did not have a legitimate business need to request signatures for.
- Learn private wallet topology (whether an address is local vs. shared vs. unknown to the victim, and which signing_path resolves), which is not information the attacker should be entitled to for addresses outside any shared address they participate in.

This corresponds to unauthorized access to and potential unauthorized spending from wallet resources — reachable purely from a paired-device message, matching the required "wallet and contract message handling" reachable path.

### Likelihood Explanation
Reaching this code only requires being an already-known correspondent device of the victim (pairing is a normal, low-friction wallet operation and correspondents are not implicitly trusted with each other's unrelated addresses). No additional privilege on the specific shared address is required, unlike the `ifRemote` path which does enforce it. The missing check is an explicit deliberate omission (commented out in code) rather than a subtle logic bug, making it straightforward to trigger.

### Recommendation
Re-enable (and properly integrate, without breaking legitimate multilateral signing flows) the cosigner check in the `ifLocal` branch: verify that `from_address` is actually a party permitted to request a signature for `body.address`/`body.signing_path` (e.g., it is itself the address owner requesting self-signature, or it is listed among the other cosigner device addresses for that specific shared address / signing path), mirroring the check already present in the `ifRemote` branch, before emitting `signing_request` or processing the unit through `handleOnlineJoint`.

### Proof of Concept
1. Attacker device A pairs with victim device V (any ordinary pairing, e.g., through a public pairing code) — a normal, low-privilege operation that does not add A as a cosigner to any of V's addresses.
2. A sends V a device message:
```
{
  subject: "sign",
  body: {
    address: "<V's local personal or shared address controlled by V>",
    signing_path: "r",
    unsigned_unit: { authors: [{ address: "<address>" }], messages: [ ... crafted payment ... ], version: ... }
  }
}
```
3. `handleMessageFromHub` resolves the address via `findAddress`; since V's device is the actual signer for this address/path, `ifLocal` fires.
4. Because the cosigner check is commented out at `wallet.js` lines 335-338, the flow proceeds directly to `callbacks.ifOk()` and emits `signing_request(objAddress, body.address, objUnit, assocPrivatePayloads, from_address="A", body.signing_path)`, triggering V's wallet UI to prompt for a signature on the attacker-supplied unit — despite A never having been granted cosigner rights on `address`. [6](#0-5)

### Citations

**File:** wallet.js (L94-99)
```javascript
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
		switch (subject){
			case "pairing":
				device.handlePairingMessage(json, device_pubkey, callbacks);
				break;
```

**File:** wallet.js (L332-404)
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
