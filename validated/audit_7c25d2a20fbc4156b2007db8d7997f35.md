Based on my investigation, I found the `findAddress` function in `wallet.js` that contains exactly the same bug-class pattern as the Langflow IDOR: **two lookup branches for the same resource where one branch enforces ownership verification and the other branch's ownership check was deliberately removed.** [1](#0-0) 

The `ifRemote` branch explicitly checks `if (!other_device_addresses.includes(from_address)) return callbacks.ifError("you are not listed as a cosigner for this address ...")` [2](#0-1) , but the `ifLocal` branch has that exact same ownership check commented out with the note "the commented check would make multilateral signing impossible" [3](#0-2) .

### Title
Missing cosigner-ownership check in `findAddress`'s local-address branch allows any paired device to trigger unauthorized signing requests for another user's address - (File: wallet.js)

### Summary
The `sign` message handler in `handleMessageFromHub` resolves the target address via `findAddress()` [4](#0-3) . `findAddress` has two symmetric outcomes for an address whose signing key lives on this device: `ifRemote` (key is on a different device) and `ifLocal` (key is on this device) [5](#0-4) . The `ifRemote` handler enforces that the requesting device (`from_address`) is actually listed as a cosigner of the wallet/address before proxying or accepting the request [2](#0-1) . The `ifLocal` handler is missing the equivalent check — the verification that "sender is a cosigner of this address" is explicitly commented out [3](#0-2) .

### Finding Description
Any correspondent (paired) device can send a `"sign"` message referencing any local address of the victim's wallet along with an attacker-crafted `unsigned_unit`/`private_payloads`. Because `ifLocal` skips the cosigner/wallet-membership check that exists in the parallel `ifRemote` branch, `findAddress` accepts the request as if the sender were a legitimate cosigner of that address, and the code proceeds to validate the unit and emit the `"signing_request"` event with the attacker's unsigned unit, private payload disclosures, and `from_address`, `signing_path` values intact [6](#0-5) . This same `findAddress`/`ifLocal` code path also backs `getSigner().sign` used when actually authorizing/signing outgoing payments [7](#0-6) , so the absence of sender validation on the multisig-key-holding side removes a defense-in-depth boundary that should ensure only genuine cosigners of a shared/wallet address can solicit a signature for that address, in a way symmetric with the remote-signer branch.

### Impact Explanation
For any multisig/shared address where the victim's device holds one of the local signing keys, an unrelated paired device can spoof itself as a legitimate cosigner and initiate signing flows for the victim's addresses, exposing sensitive contents of `signing_request` (assocPrivatePayloads, unsigned unit) and forcing repeated confirmation dialogs that could be used for social-engineering or dialog-fatigue attacks toward tricking the user into signing/spending against an attacker-controlled multisig transaction. This directly parallels the Langflow analog: one lookup path enforces "requester is authorized owner/cosigner," the other silently omits it.

### Likelihood Explanation
Reachable by any already-paired device (a normal correspondent relationship, not a privileged role) sending a single crafted `"sign"` justsaying/message over the existing device-messaging protocol — no special privileges beyond pairing are required, and the check was deliberately disabled rather than merely absent by oversight, indicating an intentional trust relaxation whose security implication (missing sender/cosigner validation vs. the analogous remote path) appears not to have been fully evaluated.

### Recommendation
Restore the cosigner-ownership verification in the `ifLocal` branch of the `"sign"` handler, mirroring the check already present in `ifRemote` (verify `from_address` is a recognized cosigner/wallet-signing-path device for `body.address` before processing the signing request), or otherwise ensure that any UI/business logic downstream of `signing_request` cannot be triggered by a non-cosigning correspondent.

### Proof of Concept
1. Attacker device D2 pairs with victim device D1 (standard correspondent pairing, no elevated trust).
2. D1 owns a local signing key for shared/multisig address `A` (one leg of a multisig wallet), which is *not* shared with D2 in `wallet_signing_paths`/`shared_address_signing_paths`.
3. D2 sends a `"sign"` message to D1: `{ address: A, signing_path: "r", unsigned_unit: {...attacker-crafted unit...} }`.
4. `handleMessageFromHub` on D1 calls `findAddress(A, "r", ...)`; since D1 holds the local key, `ifLocal` fires without ever checking that D2 is actually a party to `A`'s wallet [8](#0-7) .
5. D1 validates the crafted unit and emits `"signing_request"`, exposing private payload data to the UI/handler and prompting the user to sign a transaction chosen by an unauthorized correspondent — the exact "requester is authorized" check that protects the symmetric `ifRemote` case at [9](#0-8)  is absent here.

### Citations

**File:** wallet.js (L332-403)
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
```

**File:** wallet.js (L1233-1260)
```javascript
function findAddress(address, signing_path, callbacks, fallbackInfo){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		async function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress()) {
					const other_rows = await db.query("SELECT DISTINCT device_address FROM wallet_signing_paths WHERE wallet=? AND device_address!=?", [row.wallet, row.device_address]);
					const other_device_addresses = other_rows.map(r => r.device_address);
					return callbacks.ifRemote(row.device_address, other_device_addresses);
				}
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
			}
```

**File:** wallet.js (L2016-2029)
```javascript
		sign: function (objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature) {
			var buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
			findAddress(address, signing_path, {
				ifError: function (err) {
					throw Error(err);
				},
				ifUnknownAddress: function (err) {
					throw Error("unknown address " + address + " at " + signing_path);
				},
				ifLocal: function (objAddress) {
					signWithLocalPrivateKey(objAddress.wallet, objAddress.account, objAddress.is_change, objAddress.address_index, buf_to_sign, function (sig) {
						handleSignature(null, sig);
					});
				},
```
