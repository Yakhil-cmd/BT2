### Title
Broken Authorization Check Allows Any Paired Device to Trigger Signing Requests for Addresses It Does Not Co-Sign - (File: wallet.js)

### Summary
The Fineract CVE-2025-58137 is an IDOR where a user-controlled key (an object identifier) is accepted without verifying that the caller actually owns/controls the referenced resource. The same bug class exists in `wallet.js`'s handling of the `"sign"` device-message subject: the check that verifies the sender is actually a listed cosigner of the requested address is present for the `ifRemote` (proxy) branch but has been explicitly disabled (commented out) for the `ifLocal` branch, so any paired correspondent device can supply an arbitrary local address it does not co-sign and still reach the signing-request flow.

### Finding Description
In `handleMessageFromHub`'s `"sign"` case, the address to be signed for (`body.address`, a user-controlled key) is looked up with `findAddress`, which classifies the address as local, remote, merkle, or unknown: [1](#0-0) 

For the `ifRemote` branch (proxy case), the code correctly enforces that the requesting device is a listed cosigner before doing anything: [2](#0-1) 

But for the `ifLocal` branch — i.e. when the requested address is actually one of *our own* wallet addresses — the equivalent ownership/cosigner check has been deliberately removed, with a comment acknowledging the tradeoff: [3](#0-2) 

Once this check is bypassed, the code immediately proceeds to fire the `"signing_request"` event (for `signed_message` payloads) or validates and processes the attacker-supplied unsigned unit via `network.handleOnlineJoint`, then fires `"signing_request"` for normal payment units: [4](#0-3) 

This means the identity check that ties `from_address` (the sender of the message, verified only by device pairing/correspondence, see `device.js` `handleJustsaying`) to actual membership/cosigner status of `body.address` is missing on the path that matters most — the path where the address is genuinely one of the victim's own (possibly shared/multisig) addresses. The `device_address` used to authorize the request is never checked against `wallet_signing_paths`/`shared_address_signing_paths` for that specific address in the `ifLocal` case, unlike `ifRemote`.

Any device that is merely paired/known as a correspondent (which does not require being a wallet cosigner — see the correspondent lookup in `device.js`) can therefore send a crafted `"sign"` justsaying message naming any of the victim's local addresses as `body.address`, along with an attacker-crafted `unsigned_unit`/`signed_message`, and have the wallet engine treat it as a legitimate signing request for that address. [5](#0-4) 

### Impact Explanation
This breaks the intended authorization model for multisig/shared-address signing: the wallet software is supposed to solicit signatures only from genuine cosigners of a given address (as enforced for the remote/proxy branch), but for local addresses this restriction is absent. A malicious paired device (not a cosigner of the targeted shared/multisig address) can:
- Inject arbitrary attacker-chosen unsigned units/payment messages that reference the victim's addresses as authors, forcing them through unit validation (`network.handleOnlineJoint`) and surfacing spoofed `"signing_request"`/confirmation-dialog events to the victim, misrepresenting itself as an authorized cosigner requesting a legitimate multisig transaction.
- Abuse this to social-engineer the victim into approving a transaction they believe originates from a legitimate cosigner, when it in fact originates from an untrusted device — undermining the cosigner-authorization guarantee that shared/multisig wallets rely on for fund safety.

This matches the CVE's authorization-bypass pattern: a user-supplied identifier (`body.address`) is accepted and acted upon without verifying the caller's actual right to act on that identifier, in one of the two symmetric code paths (`ifLocal` vs `ifRemote`) that should apply the same check.

### Likelihood Explanation
Any device that has been paired as a correspondent (a low bar — pairing does not require being a cosigner of any particular shared address) can immediately exploit this by sending a `"sign"` justsaying message; no proof of cosigner status is required by the vulnerable branch. The attack requires no privilege beyond being a paired device, matching the "unprivileged...paired device" reachability the analysis targets.

### Recommendation
Restore/implement the ownership check in the `ifLocal` branch symmetric to the `ifRemote` branch: before honoring a `"sign"` request for a local address, verify that `from_address` is actually listed as a cosigner device for that specific `address`/`signing_path` combination (e.g., via `wallet_signing_paths` / `shared_address_signing_paths`), rejecting the request with `callbacks.ifError("you are not listed as a cosigner for this address ...")` otherwise, exactly as is already done for `ifRemote`.

### Proof of Concept
1. Pair a device `M` (malicious) with the victim's wallet device `V` as an ordinary correspondent (no cosigner relationship on any shared address required).
2. `M` learns/guesses one of `V`'s addresses, e.g. a shared multisig address `SA` that `M` is not a signer on.
3. `M` sends `V` a `hub/message`-wrapped justsaying with `subject: "sign"`, `body: {address: SA, signing_path: "r", unsigned_unit: {...attacker-crafted unit with SA as author...}}`.
4. On `V`, `handleMessageFromHub` → `findAddress(SA, "r", ...)` resolves `ifLocal` (since `SA` belongs to `V`'s own wallet), and because the cosigner check is commented out, `V` proceeds to validate/process the unit and emit a `"signing_request"` event as if `M` were a legitimate cosigner, despite `M` never being verified as a cosigner of `SA`.

### Citations

**File:** wallet.js (L331-333)
```javascript
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
```

**File:** wallet.js (L334-339)
```javascript
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
```

**File:** wallet.js (L340-368)
```javascript
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
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
