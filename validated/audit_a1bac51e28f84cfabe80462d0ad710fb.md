### Title
Missing cosigner-permission check in `wallet.js` `"sign"` handler lets any paired device trigger signing requests for local addresses it does not co-sign - ([File: wallet.js])

### Summary
The `"sign"` case in `handleMessageFromHub()` intentionally skips verifying that the requesting device is actually a registered cosigner of the target address when the address is local (`ifLocal`). The check exists for the `ifRemote` branch but was commented out for `ifLocal`, allowing any correspondent (paired) device to request a signature for *any* of the victim's `my_addresses`/`shared_addresses`, not just ones the sender legitimately co-signs.

### Finding Description
In `wallet.js`, the `"sign"` message handler resolves the target address via `findAddress(body.address, body.signing_path, {...})` [1](#0-0) . In the `ifRemote` branch, the code explicitly checks that the sender (`from_address`) is one of the `other_device_addresses` (i.e., an actual cosigner) before proxying the signing offer: `if (!other_device_addresses.includes(from_address)) return callbacks.ifError("you are not listed as a cosigner for this address ...")` [2](#0-1) .

However, in the `ifLocal` branch — reached when `body.address` is one of the receiving device's own `my_addresses` or `shared_addresses` — the equivalent check is present only as a **commented-out** block: `// the commented check would make multilateral signing impossible ... if (sender_rows.length !== 1) return callbacks.ifError("sender is not cosigner of this address")`, and instead the code proceeds directly to `callbacks.ifOk()` and emits `signing_request` for any correspondent device [3](#0-2) .

This means any device that is a correspondent of the victim (paired for any reason — chat, textcoin exchange, an unrelated shared/multisig arrangement, etc.) can craft a `"sign"` message naming an address it has no legitimate relationship to and cause the victim's wallet to emit a `signing_request` event for that address, complete with an attacker-fully-controlled unsigned unit and (optionally) private payloads [4](#0-3) . Reachability requires only being an already-known correspondent device; the "sign" subject is not on the list of subjects allowed from non-correspondents, but pairing itself is trivial and is one of the always-allowed subjects [5](#0-4) .

This is analogous to the Jenkins HashiCorp Vault Plugin flaw (CVE-2022-36888): a caller with only baseline access (there, `Overall/Read`; here, being any paired correspondent device) can specify an arbitrary path/target (there, a Vault secret path; here, an address/signing_path) to an endpoint that is supposed to be gated by a stronger authorization check (there, a Vault-credential permission; here, cosigner membership), and the check was never enforced.

### Impact Explanation
`ocore` itself does not auto-sign on receipt of `signing_request` — that is left to the consuming application/UI. However, the vulnerability is a genuine missing-authorization defect in the ocore library: any headless, bot-operated, or otherwise automated wallet/service built on ocore that listens for `signing_request` and applies weaker or no additional cosigner verification (a reasonable assumption, since ocore's own comment acknowledges the check "would make multilateral signing impossible" and was deliberately dropped) can be tricked into presenting or auto-approving a signature request for a multisig/shared address to a device that is not one of its legitimate cosigners. If such a signature is obtained, it directly contributes toward completing an unauthorized transaction from a shared address, i.e., potential unauthorized spending/fund loss. Even where the UI safely prompts the human user, an attacker-controlled correspondent can spam signing prompts for addresses unrelated to it, creating social-engineering/UX-based fraud vectors that a properly permission-checked implementation would reject outright.

### Likelihood Explanation
The precondition — becoming a "correspondent" (paired device) of the victim — is low-effort and analogous to the "unprivileged" access level in the referenced CVE (any user with only baseline read access). Pairing does not imply any cosigning relationship, so a large population of paired devices (chat contacts, textcoin senders, etc.) could exploit this. The remaining exploitation step (getting an operator/automation to complete the signature) depends on the specific downstream wallet implementation, which lowers but does not eliminate likelihood, since the missing check is at the ocore library layer that many wallets depend on.

### Recommendation
Restore and enforce the commented-out authorization check in the `ifLocal` branch of the `"sign"` handler: before emitting `signing_request` (or auto-signing) for a `my_addresses`/`shared_addresses` target, verify that `from_address` is actually a registered signing-path holder/cosigner of `body.address` (e.g., via `wallet_signing_paths` / `shared_address_signing_paths`), mirroring the check already performed in the `ifRemote` branch.

### Proof of Concept
1. Attacker device pairs with the victim's wallet device (trivial, low-privilege action supported by ocore's pairing flow) [6](#0-5) .
2. Attacker sends a `"sign"` message to the victim over the hub with `body.address` set to one of the victim's shared/multisig addresses that the attacker is *not* a cosigner of, along with an attacker-crafted `unsigned_unit`.
3. `handleMessageFromHub` routes this to the `"sign"` case; `findAddress` resolves it as local; the missing cosigner check is bypassed and `signing_request` is emitted to the victim application layer with the attacker-controlled unit [7](#0-6) .
4. Depending on the victim's automation/UI handling of `signing_request`, this can lead to unintended signature generation or, at minimum, unauthorized signing-request injection for addresses outside the attacker's authority.

### Citations

**File:** wallet.js (L331-371)
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```

**File:** device.js (L213-220)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
```

**File:** device.js (L797-848)
```javascript
// {pairing_secret: "random string", device_name: "Bob's MacBook Pro", reverse_pairing_secret: "random string"}
function handlePairingMessage(json, device_pubkey, callbacks){
	var body = json.body;
	var from_address = objectHash.getDeviceAddress(device_pubkey);
	if (!ValidationUtils.isNonemptyString(body.pairing_secret))
		return callbacks.ifError("correspondent not known and no pairing secret");
	if (!ValidationUtils.isNonemptyString(json.device_hub)) // home hub of the sender
		return callbacks.ifError("no device_hub when pairing");
	if (json.device_hub.length > 200)
		return callbacks.ifError("device_hub too long");
	if (!network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub))
		return callbacks.ifError("invalid device_hub URL");
	if (!ValidationUtils.isNonemptyString(body.device_name))
		return callbacks.ifError("no device_name when pairing");
	if (body.device_name.length > 100)
		return callbacks.ifError("device_name too long");
	if ("reverse_pairing_secret" in body && !ValidationUtils.isNonemptyString(body.reverse_pairing_secret))
		return callbacks.ifError("bad reverse pairing secret");
	eventBus.emit("pairing_attempt", from_address, body.pairing_secret);
	db.query(
		"SELECT is_permanent FROM pairing_secrets WHERE pairing_secret IN(?,'*') AND expiry_date>"+db.getNow()+" ORDER BY (pairing_secret=?) DESC LIMIT 1", 
		[body.pairing_secret, body.pairing_secret], 
		function(pairing_rows){
			if (pairing_rows.length === 0)
				return callbacks.ifError("pairing secret not found or expired");
			// add new correspondent and delete pending pairing
			var safe_device_name = body.device_name.replace(/<[^>]*>?/g, '');
			db.query(
				"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,1)", 
				[from_address, device_pubkey, json.device_hub, safe_device_name],
				function(){
					db.query( // don't update name if already confirmed
						"UPDATE correspondent_devices SET is_confirmed=1, name=? WHERE device_address=? AND is_confirmed=0", 
						[safe_device_name, from_address],
						function(){
							db.query("UPDATE correspondent_devices SET is_blackhole=0 WHERE device_address=?", [from_address], function(){
								eventBus.emit("paired", from_address, body.pairing_secret);
								if (pairing_rows[0].is_permanent === 0){ // multiple peers can pair through permanent secret
									db.query("DELETE FROM pairing_secrets WHERE pairing_secret=?", [body.pairing_secret], function(){});
									eventBus.emit('paired_by_secret-'+body.pairing_secret, from_address);
								}
								if (body.reverse_pairing_secret)
									sendPairingMessage(json.device_hub, device_pubkey, body.reverse_pairing_secret, null);
								callbacks.ifOk();
							});
						}
					);
				}
			);
		}
	);
}
```
