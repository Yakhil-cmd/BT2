### Title
Unauthenticated correspondent can hijack a local multi-device signing session by impersonating a cosigner - ([File: wallet.js])

### Summary
The `"sign"` subject handler in `handleMessageFromHub` (`wallet.js`) processes signing requests for locally-hosted addresses (`findAddress`'s `ifLocal` branch) without verifying that the sending device is actually one of the recognized cosigners/wallet members for that address. The authorization check that used to enforce this was intentionally commented out, mirroring the n8n bug class where a WebSocket handler resumed a "waiting" session using only a public identifier, without checking that the caller was authorized to interact with it.

### Finding Description
In `wallet.js`, `handleMessageFromHub`'s `"sign"` case validates message shape (address format, signing path regex, unit structure, payload hashes) but performs no check that `from_address` (the device that sent the `sign` message) is a legitimate cosigner of `body.address`. [1](#0-0) 

When `findAddress` resolves the address locally (`ifLocal`), the handler immediately proceeds to build/validate the unit and fires the `"signing_request"` event that triggers the wallet UI's signing confirmation dialog — with the explicit removed check:
```
ifLocal: function(objAddress){
    // the commented check would make multilateral signing impossible
    //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
    //    if (sender_rows.length !== 1)
    //        return callbacks.ifError("sender is not cosigner of this address");
        callbacks.ifOk();
        ...
``` [2](#0-1) 

Any device that is merely a *paired correspondent* (device.js pairing only requires knowledge of a `pairing_secret`, not any relationship to a specific wallet) can send a `"sign"` message referencing:
- any `address` this device knows to be locally hosted (my address, or the local leaf of a shared/multisig address reached via `findAddress`'s recursive resolution — `wallet.js` `findAddress`, lines 1233-1316), and
- an arbitrary `unsigned_unit` payload, crafted by the attacker. [3](#0-2) 

Because there is no verification that the sender is one of the address's actual co-signers, an attacker who is simply paired with the victim's device (a trivial requirement — pairing is a lightweight, unauthenticated handshake keyed only on a `pairing_secret`, see `device.js` `handlePairingMessage`) can:
1. Trigger unlimited signing-confirmation prompts on the victim's wallet UI for attacker-chosen units/addresses ("prompt bombing" / UI hijacking), confusing the user into approving a malicious spend they did not initiate.
2. In the `ifRemote` branch, similarly exploit `other_device_addresses.includes(from_address)` — this check does validate correctly for the proxy/multisig case, but the local (`ifLocal`) path lacks the equivalent enforcement, creating an inconsistency where one code path is protected and the other is not. [4](#0-3) 

This matches the n8n vulnerability's root cause pattern precisely: a handler keyed by a semi-public identifier (device/execution/address) resumes/attaches to a privileged "waiting" interaction without validating that the requester is one of the parties legitimately entitled to interact with that session.

### Impact Explanation
This allows an unauthorized paired device to:
- Repeatedly invoke the wallet's signing confirmation UI for arbitrary attacker-crafted transactions bound to the victim's own address, increasing the chance the victim approves a malicious unit through social engineering/prompt fatigue, leading to unauthorized spending of the victim's funds.
- Abuse the "multilateral signing" path (used for arbiter/prosaic contracts) to inject spoofed signing requests into flows meant for a specific designated peer, since only pairing (not wallet cosigner membership) is required as a correspondent.

Given that the primary asset at risk is fund custody via a confirmation dialog, and successful exploitation requires user interaction (approving the prompt) but not any legitimate cosigner relationship, this is consistent with Medium severity, matching the CVSS profile of the original advisory (`AC:H`, requires certain conditions and some interaction, `PR:N`, `UI:N` in the source, no direct integrity/availability of chain but wallet-level integrity impact).

### Likelihood Explanation
Exploitation requires:
- The attacker device to be a paired correspondent of the victim (trivial to achieve if pairing codes/QR are shared casually, or if pairing is left open, similar to Hosted Chat left set to "None" auth in the original advisory).
- Knowledge of a victim address hosted locally by that device (addresses are often shared publicly for payments, or observable from prior interactions/shared-address setup).
No knowledge of private keys or wallet membership is needed — only correspondence with the device.

### Recommendation
Reinstate and generalize the cosigner-authorization check that was commented out in the `ifLocal` branch of the `"sign"` handler in `wallet.js`: before emitting `"signing_request"` or validating the attacker-supplied unit, verify `from_address` is a genuine cosigner/member device for `body.address` (query `wallet_signing_paths` / `shared_address_signing_paths` for the resolved wallet or shared address and confirm `from_address` is present), consistent with the check already enforced in the `ifRemote` branch (`other_device_addresses.includes(from_address)`). Reject with `callbacks.ifError("sender is not cosigner of this address")` otherwise.

### Proof of Concept
1. Attacker device pairs with victim's wallet via a normal pairing exchange (`device.js` `handlePairingMessage`), becoming a `correspondent_devices` entry with no wallet relationship.
2. Attacker learns the victim's locally-hosted address `X` (e.g. observed on-chain, or from a prior payment).
3. Attacker sends a `hub/message` with `subject: "sign"`, `body: { address: X, signing_path: "r", unsigned_unit: <attacker-crafted payment unit spending from X to attacker's address> }`.
4. `handleMessageFromHub` → `"sign"` case validates format, calls `findAddress(X, "r", ...)`, which resolves `ifLocal` because `X` is hosted on the victim's device.
5. Without any cosigner check, `callbacks.ifOk()` fires and `eventBus.emit("signing_request", ...)` triggers the wallet UI signing dialog for the attacker's unit, repeatable indefinitely, increasing likelihood the victim inadvertently approves a malicious spend.

### Citations

**File:** wallet.js (L251-278)
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

**File:** wallet.js (L1233-1259)
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
```
