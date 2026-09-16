### Title
Missing cosigner authorization check allows any correspondent device to trigger unauthorized signing requests for local multisig addresses - (File: wallet.js)

### Summary
CVE-2023-40660 describes OpenSC allowing an already-authenticated card/token session's login state to be reused by other unauthorized processes because the token internally tracks "logged in" status rather than requiring per-operation proof of authorization. The reachable analog in ocore is in the device-message "sign" handler in [1](#0-0) , where the `ifLocal` branch of `findAddress` explicitly skips the check that the message sender (`from_address`) is actually a registered cosigner of the wallet/address before proceeding to process the signing request.

### Finding Description
In `handleMessageFromHub`'s `"sign"` case, when a device message requests a signature for a unit against a **local** address (`ifLocal`), the code that should validate the requester's cosigner membership is commented out: [2](#0-1) 

The comment says "the commented check would make multilateral signing impossible" — but its removal means that *any* device that is merely a paired correspondent (added via the `pairing` subject, which requires only a `pairing_secret`, see `handlePairingMessage` in [3](#0-2) ) can send a `"sign"` message referencing any local wallet address, and it will be processed and forwarded into `signing_request` for UI confirmation and/or `network.handleOnlineJoint` — without the correspondent being one of the wallet's actual cosigners (`extended_pubkeys`) as would be checked in the disabled query.

Contrast this with the `ifRemote` branch, just below, which does perform the equivalent check explicitly: [4](#0-3) 
`ifRemote` verifies `other_device_addresses.includes(from_address)` — i.e., that the sender is a legitimate cosigner — before forwarding/proxying a signing request. The `ifLocal` branch has no equivalent authorization gate; it relies only on device-message authenticity (signature verification performed earlier in `device.js`/`network.js` hub-message handling, e.g. [5](#0-4) ) but not on cosigner *authorization* for the specific address being asked to sign.

This mirrors the OpenSC bug class: a device's paired/authenticated status (proven via device-message signature + pairing) is treated as sufficient "logged-in" state to authorize a sensitive operation (requesting a signature on a specific address), instead of re-checking authorization scope (is this device actually a cosigner of *this* address) for each request.

### Impact Explanation
If reachable in a live shared/multisig wallet setup, any correspondent device (even one paired legitimately for an unrelated purpose, e.g. chat, textcoin claim, or via a permanent pairing secret) could submit a "sign" request naming a wallet address it doesn't cosign. The consequence depends on downstream UI/headless behavior:
- At minimum, this triggers unwanted `signing_request` events / unit validation work (`network.handleOnlineJoint`) for units the sender has no legitimate right to request signing on, which can be used to probe wallet state, cause spurious confirmation dialogs, or (in headless/automated signer configurations that auto-approve based on address/signing_path without checking the sender identity) result in unauthorized transaction signing — leading to potential unauthorized spending from the wallet's own funds if the confirming logic doesn't independently verify the correspondent's cosigner status.
- This falls under "AA/wallet fund loss" concern classes since a paired-but-unauthorized device gains the ability to initiate signing flows for addresses it does not co-own.

### Likelihood Explanation
Likelihood is moderate: exploitation requires the attacker's device to already be a paired correspondent of the victim (via `pairing_secret`, including permanent pairing secrets described in `getOrGeneratePermanentPairingInfo`, [6](#0-5) ), but does not require the attacker to be a cosigner of the targeted wallet address. Given that pairing is a routine, low-friction operation (e.g., establishing a chat/support connection), an attacker who pairs with a victim device for any reason could then send crafted `"sign"` messages targeting the victim's local wallet addresses.

### Recommendation
Restore (or reimplement in a way compatible with legitimate multilateral signing) the cosigner-authorization check in the `ifLocal` branch of the `"sign"` handler in `wallet.js`, verifying that `from_address` corresponds to a registered cosigner (or otherwise authorized party, e.g. via `wallet_signing_paths`/`extended_pubkeys`) of `body.address` before emitting `signing_request` or validating/forwarding the unit. If multilateral signing (contract counterparties signing the same message from different addresses) must be supported, the check should be scoped to explicitly permit that case (e.g., verifying the requester is a legitimate contract counterparty via signed_message context) rather than removing address-cosigner verification entirely.

### Proof of Concept
1. Device B pairs with Device A using any pairing secret (temporary or permanent) — no relationship to Device A's multisig wallet is required. `handlePairingMessage`, [7](#0-6) .
2. Device B crafts and sends a `"sign"` device message to Device A referencing Device A's local multisig wallet address (learned via external observation, e.g. from a public unit) and an arbitrary `unsigned_unit`.
3. Device A's `handleMessageFromHub` reaches the `"sign"` case, calls `findAddress`, and hits `ifLocal`, where the disabled cosigner check at `wallet.js:335-338` means Device B's authorization is never verified.
4. Device A proceeds to validate/emit `signing_request` for the address on behalf of a device (B) that is not actually a cosigner, exposing wallet-state-dependent processing and, in automated/headless-signing configurations, risking unauthorized signature issuance for funds the requester does not own.

### Citations

**File:** wallet.js (L331-339)
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```

**File:** device.js (L163-172)
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
```

**File:** device.js (L778-795)
```javascript
function getOrGeneratePermanentPairingInfo(handlePairingInfo){
	db.query("SELECT pairing_secret FROM pairing_secrets WHERE is_permanent=1 ORDER BY expiry_date DESC LIMIT 1", [], function(rows){
		var pairing_secret;
		if (rows.length) {
			pairing_secret = rows[0].pairing_secret;
		} else {
			pairing_secret = crypto.randomBytes(9).toString("base64");
			db.query("INSERT INTO pairing_secrets (pairing_secret, is_permanent, expiry_date) VALUES(?, 1, '2038-01-01')", [pairing_secret]);
		}
		var pairingInfo = {
			pairing_secret: pairing_secret,
			device_pubkey: objMyPermanentDeviceKey.pub_b64,
			device_address: my_device_address,
			hub: my_device_hub
		};
		handlePairingInfo(pairingInfo);
	});
}
```

**File:** device.js (L798-847)
```javascript
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
```
