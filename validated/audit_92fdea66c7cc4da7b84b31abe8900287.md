I have enough evidence to conclude on the strongest analog found.

### Title
Missing cosigner-authorization check in `wallet.js` "sign" handler discloses private payment details to unauthorized paired devices - (File: wallet.js)

### Summary
The CVE describes ownCloud bypassing password/authentication for a protected resource via an alternate, less-restrictive code path (the preview generator), which does not enforce the same access checks as the primary download path. In `ocore`, the "sign" message handler in [1](#0-0)  exposes an analogous pattern: a request coming from *any* paired device (correspondent) is processed for a locally-hosted shared/multisig address without verifying that the requesting device is actually one of the address's legitimate cosigners.

### Finding Description
When a device receives a `"sign"` request through the hub, it resolves the target address via `findAddress()` and, on `ifLocal`, immediately proceeds to disclose sensitive unit/payment content by firing the `"signing_request"` event — without checking that `from_address` (the requester) is actually a registered cosigner of that shared address. The check that would enforce this is explicitly present in the code but commented out: [2](#0-1) 

The comment even acknowledges the omission: *"the commented check would make multilateral signing impossible"*. Contrast this with the `ifRemote` branch of the very same handler, which does correctly verify authorization before forwarding a signing request: [3](#0-2) 

In `ifRemote`, the code explicitly checks `other_device_addresses.includes(from_address)` before honoring the signing request, i.e., verifying the sender is a genuine cosigner. In `ifLocal`, this equivalent authorization step is missing entirely. As a result, any correspondent (paired) device that knows a locally used multisig/shared address and one of its signing paths can trigger disclosure of the full unsigned unit content and the decrypted `private_payloads` (payment amounts, addresses, blinding factors) via the `"signing_request"` event — content intended only for legitimate cosigners of that shared address.

`findAddress()` itself does not verify the caller's authorization either; it only checks that the address/signing_path combination exists locally: [4](#0-3) 

### Impact Explanation
This is an authorization-bypass analogous to the ownCloud preview bug: a secondary/alternate handling branch (`ifLocal`) skips an authorization check that its sibling branch (`ifRemote`) enforces correctly. A paired-but-unauthorized device can force disclosure of private payment content (amounts, addresses, blinding) attached to a shared address it does not actually cosign, and can also trigger UI confirmation dialogs presenting attacker-supplied payment data as if from a legitimate cosigner, creating a path toward social-engineering the victim into approving unintended spends from a shared/multisig wallet address, since the disclosed unit is subsequently fed into `network.handleOnlineJoint` and surfaced to the user for signature approval.

### Likelihood Explanation
Requires only that the attacker be paired with the victim as a device correspondent — an unprivileged, easily obtainable relationship (paired device is explicitly a permitted trust boundary), and that the attacker knows or guesses a shared address and one of its signing paths that the victim device locally hosts, which is plausible in multi-cosigner (multisig/prosaic/arbiter-contract) setups where all cosigners' devices are mutually paired.

### Recommendation
Restore/implement the commented-out authorization check in the `ifLocal` branch of the `"sign"` handler in `wallet.js`, verifying `from_address` against the actual list of cosigner device addresses for the wallet/shared address (mirroring the check already done in `ifRemote`) before processing the request or emitting `"signing_request"`.

### Proof of Concept
1. Device A pairs with victim Device B (legitimate correspondent relationship, no cosigning rights on B's shared address `S`).
2. Device A learns/guesses that address `S` (a shared/multisig address hosted locally on B) uses signing path `r.1.0` (paths are often predictable/standard).
3. Device A sends a hub-relayed `"sign"` message to B: `{address: S, signing_path: "r.1.0", unsigned_unit: {...crafted unit...}, private_payloads: {...}}`.
4. B's `handleMessageFromHub` resolves `findAddress(S, "r.1.0")` → `ifLocal` (since B hosts `S` locally with that path) — no cosigner check is performed on A.
5. B decrypts/validates and emits `"signing_request"`, displaying the attacker-crafted payment details to the user and processing/validating the private payloads, even though A is not a legitimate cosigner of `S`.

### Citations

**File:** wallet.js (L251-256)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
```

**File:** wallet.js (L332-349)
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
```

**File:** wallet.js (L374-392)
```javascript
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

**File:** wallet.js (L1265-1287)
```javascript
				"SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
				WHERE shared_address=? AND ( signing_path=? OR " + prefix + "=SUBSTR(?, 1, LENGTH(signing_path)+1) )", 
				[address, signing_path, signing_path],
				async function(sa_rows){
					if (sa_rows.length > 1)
						throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
					if (sa_rows.length === 1) {
						var objSharedAddress = sa_rows[0];
						var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
						var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
						if (objSharedAddress.address === '') {
							return callbacks.ifMerkle(bLocal);
						} else if(objSharedAddress.address === 'secret') {
							return callbacks.ifSecret();
						}
						let newFallbackInfo = null;
						if (!bLocal) {
							newFallbackInfo = {};
							newFallbackInfo.device_address = objSharedAddress.device_address;
							const other_rows = await db.query("SELECT DISTINCT device_address FROM shared_address_signing_paths WHERE shared_address=? AND device_address!=?", [address, objSharedAddress.device_address]);
							newFallbackInfo.other_device_addresses = other_rows.map(r => r.device_address);
						}
						return findAddress(objSharedAddress.address, relative_signing_path, callbacks, newFallbackInfo);
```
