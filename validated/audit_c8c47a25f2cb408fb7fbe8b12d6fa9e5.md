## Finding [1](#0-0) 

### Title
Missing cosigner-authorization check on local "sign" requests allows any paired device to enumerate wallet addresses and spoof signing prompts - (File: wallet.js)

### Summary
In `wallet.js`'s `handleMessageFromHub`, the `"sign"` message handler resolves the target address via `findAddress()` and then branches on whether the address is hosted locally (`ifLocal`) or on a remote cosigner device (`ifRemote`). The `ifRemote` branch explicitly verifies that the requesting device is a listed cosigner of the address before forwarding the request:
```
if (!other_device_addresses.includes(from_address))
    return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
``` [2](#0-1) 

But the `ifLocal` branch — reached when the address is one this node actually hosts a private key for — has the equivalent check deliberately commented out:
```
// the commented check would make multilateral signing impossible
//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
//    if (sender_rows.length !== 1)
//        return callbacks.ifError("sender is not cosigner of this address");
``` [3](#0-2) 

This is directly analogous to the Discourse `discourse-policy` flaw: the object (here, a signable address/unit) is loaded and acted upon without a corresponding "does this caller have the right to act on this object" check, even though the exact same check exists and is enforced on a sibling code path.

### Finding Description
`findAddress()` locates an address purely by whether it is `local` (hosted by this device) or requires forwarding to `remote` cosigners — it does not encode "is the requester allowed to interact with this address." The `ifRemote` branch compensates for this by independently checking `other_device_addresses.includes(from_address)` before honoring the request. The `ifLocal` branch has no such compensating check: any paired correspondent device (`from_address`) that knows a BASE32 address of the victim's wallet can send a `"sign"` message for it, and if `findAddress` reports the address as local, the handler unconditionally calls `callbacks.ifOk()` and emits a `"signing_request"` event carrying the address, wallet info, unsigned unit, and any private payloads back up to the host application/UI [4](#0-3) .

The three possible outcomes for a given address are distinguishable over the wire:
- `ifUnknownAddress` → generic "not aware of address" error, deferred handling [5](#0-4) 
- `ifRemote` and not a listed cosigner → explicit "you are not listed as a cosigner for this address" error [2](#0-1) 
- `ifLocal` → immediate `ifOk()` acceptance and a signing/confirmation flow is silently kicked off on the victim device

This differentiation lets any paired device enumerate which addresses the victim node actually hosts private keys for (information disclosure, exactly like the Discourse bug's "differentiated error responses" used to determine which post IDs have policies), and, more seriously, lets it unconditionally trigger a signing/confirmation workflow for a local address it has no legitimate multisig relationship with — bypassing the very authorization check ("sender is cosigner of this address") that the codebase itself considers necessary and enforces on the remote path.

### Impact Explanation
- Information disclosure: an unprivileged paired device can probe arbitrary addresses and learn, via distinguishable responses, which addresses are locally-controlled wallet/shared addresses of the victim — private wallet topology that should not be exposed to arbitrary correspondents.
- Spoofed signing prompts: because the `ifLocal` cosigner check is skipped, any correspondent (not just legitimate multisig cosigners) can push crafted unsigned units/private payloads into the victim's signing/confirmation pipeline (`eventBus.emit("signing_request", ...)`), which downstream wallet UIs use to prompt the user to approve a transaction. This creates a phishing-style vector for unauthorized spending: a malicious correspondent can repeatedly inject spend requests dressed up as legitimate multisig cosigning requests for addresses the victim controls, increasing the chance of a user mistakenly approving unauthorized fund movement.

### Likelihood Explanation
Any device that has been paired/correspondent with the victim (a normal, low-privilege relationship — no special wallet membership required) can send this message; the only precondition is discovering or guessing a BASE32 address string that the victim hosts. No signature bypass, race condition, or privileged network position is required — this is directly reachable by any paired device sending a `"sign"` message over its already-established encrypted device channel.

### Recommendation
Restore (in a working form) the missing authorization check in the `ifLocal` branch of the `"sign"` handler: verify that `from_address` is actually a listed cosigner/device-address associated with `body.address`'s wallet (via `wallet_signing_paths`/`extended_pubkeys`, or the shared-address signer table) before calling `callbacks.ifOk()` and emitting `"signing_request"`. This mirrors the check already present and enforced in the `ifRemote` branch, and would eliminate both the enumeration and spoofed-signing-request vectors.

### Proof of Concept
1. Pair device `M` (attacker) with victim device `V` as an ordinary correspondent (no shared/multisig address relationship established).
2. `M` sends a `hub/message` justsaying to `V` with `subject: "sign"`, `body.address` set to a BASE32 address `M` suspects `V` hosts, a fabricated `body.signing_path` (e.g. `"r"`), and a `body.unsigned_unit` with an author matching `body.address`.
3. On `V`: `findAddress` resolves the address; if it is local to `V`, the code reaches `ifLocal` at wallet.js:334, skips the (commented-out) cosigner check, and immediately calls `callbacks.ifOk()` and emits `"signing_request"` — regardless of whether `M` is actually a cosigner of that address.
4. Repeating the process for multiple guessed addresses lets `M` distinguish "local" (silent accept + signing UI triggered) from "unknown" (`ifUnknownAddress`) from "remote-but-not-cosigner" (`ifRemote` explicit rejection), fully enumerating `V`'s locally-hosted wallet addresses and being able to inject arbitrary signing prompts for them.

### Citations

**File:** wallet.js (L331-392)
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
```

**File:** wallet.js (L396-400)
```javascript
					ifUnknownAddress: function(){
						callbacks.ifError("not aware of address "+body.address+" but will see if I learn about it later");
						eventBus.once("new_address-"+body.address, function(){
							// rewrite callbacks to avoid duplicate unlocking of mutex
							handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, { ifOk: function(){}, ifError: function(){} });
```
