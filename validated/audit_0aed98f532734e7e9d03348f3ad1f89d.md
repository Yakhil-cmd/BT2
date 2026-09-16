### Title
Race Condition in One-Time Pairing Secret Consumption Allows Unauthorized Device Pairing — ([File: device.js])

### Summary
`handlePairingMessage()` in `device.js` checks whether a pairing secret is valid and then, in a separate, unsynchronized step, deletes the one-time secret. Because the "check" (SELECT) and the "consume" (DELETE) are not atomic and are not serialized by `mutex`, two concurrent pairing requests carrying the same one-time secret can both pass validation before the secret is deleted, letting more than one device register as a confirmed correspondent using what was meant to be a single-use secret. This mirrors the GitLab CVE-2022-4037 pattern: a race condition between a verification check and the consumption of a token intended to be single-use, enabling an unintended party to be treated as legitimately verified/paired.

### Finding Description
`handlePairingMessage()` performs three sequential, unlocked async DB operations:

1. `SELECT is_permanent FROM pairing_secrets WHERE pairing_secret IN(?,'*') AND expiry_date>NOW() ...` [1](#0-0) 
2. `INSERT ... INTO correspondent_devices (..., is_confirmed) VALUES (...,1)` immediately confirming the correspondent [2](#0-1) 
3. Only afterward, for non-permanent secrets: `DELETE FROM pairing_secrets WHERE pairing_secret=?` [3](#0-2) 

There is no `mutex.lock` around this sequence (unlike other stateful flows in the codebase, e.g. `wallet.js`'s `mutex.lock(["from_hub"], ...)` serialization of hub messages) [4](#0-3) , and no DB transaction wraps steps 1–3. Two `handlePairingMessage` invocations for the same one-time `pairing_secret` (e.g., arriving from two different device pubkeys nearly simultaneously) can both pass the expiry/validity check at step 1 before either reaches the DELETE at step 3, so both are inserted into `correspondent_devices` with `is_confirmed=1` and both fire the `"paired"` event [5](#0-4) .

This breaks the intended single-use invariant of one-time pairing secrets (as opposed to `is_permanent=1` secrets which are explicitly meant for multiple peers) [3](#0-2) . A one-time pairing secret is typically embedded in a QR code / link shared out-of-band with exactly one intended peer; the race condition allows a second, unintended device to also complete pairing if it can submit its pairing request in the same narrow window (e.g., by racing the intended recipient, or by an attacker who intercepts/observes the secret in transit).

### Impact Explanation
Once paired as a confirmed correspondent, an attacker's device is treated by `wallet.js`'s `handleMessageFromHub` as a trusted counterparty for subsequent device-message flows, including cosigning requests (`"sign"` case, which accepts unsigned units and private payloads from any correspondent) [6](#0-5) , multisig wallet setup (`"create_new_wallet"`, `"my_xpubkey"`) [7](#0-6) , and private payment/contract message handling. This can lead to unauthorized parties inserting themselves into shared-address/multisig workflows or receiving private payment chains intended for the legitimate peer, undermining the integrity of wallet-to-wallet trust that private payments and multi-signature composition rely on.

### Likelihood Explanation
Exploitation requires winning a narrow timing window between the SELECT and DELETE on a single-use pairing secret, which requires the attacker to know or intercept the secret and race the legitimate pairing attempt (or otherwise send two pairing requests using the same secret in quick succession). This is a genuine race condition (not attacker-controlled timing at will), so likelihood is moderate — it requires network-level timing control but no cryptographic break, matching the same bug class and exploitation difficulty as the referenced GitLab race condition.

### Recommendation
Serialize pairing-secret consumption per `pairing_secret` (e.g., `mutex.lock([pairing_secret], ...)`) and make the check-and-delete atomic — for example, perform `DELETE ... WHERE pairing_secret=? RETURNING is_permanent` (or an equivalent atomic UPDATE/DELETE-then-check-affected-rows) before inserting into `correspondent_devices`, only proceeding with pairing if the delete/claim actually affected a row for non-permanent secrets.

### Proof of Concept
1. Attacker obtains or intercepts a victim's one-time pairing secret `S` (e.g., a link meant for one peer).
2. Attacker's device and the legitimate peer's device both send a `pairing` message containing `pairing_secret: S` to the hub at nearly the same time.
3. Both requests reach `handlePairingMessage()` and execute the `SELECT ... WHERE pairing_secret IN(?,'*') AND expiry_date>NOW()` check before either's `DELETE FROM pairing_secrets` completes [8](#0-7) .
4. Both devices get inserted into `correspondent_devices` with `is_confirmed=1`, and both receive the `"paired"` event — the attacker is now a trusted correspondent despite the secret being intended for one-time use.

### Citations

**File:** device.js (L816-837)
```javascript
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
```

**File:** wallet.js (L63-81)
```javascript
// one of callbacks MUST be called, otherwise the mutex will stay locked
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});
```

**File:** wallet.js (L150-171)
```javascript
			case "create_new_wallet":
				// {wallet: "base64", wallet_definition_template: [...]}
				walletDefinedByKeys.handleOfferToCreateNewWallet(body, from_address, callbacks);
				break;
			
			case "cancel_new_wallet":
				// {wallet: "base64"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				walletDefinedByKeys.deleteWallet(body.wallet, from_address, callbacks.ifOk);
				break;
			
			case "my_xpubkey": // allowed from non-correspondents
				// {wallet: "base64", my_xpubkey: "base58"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				if (!ValidationUtils.isNonemptyString(body.my_xpubkey))
					return callbacks.ifError("no my_xpubkey");
				if (body.my_xpubkey.length > 112)
					return callbacks.ifError("my_xpubkey too long");
				walletDefinedByKeys.addDeviceXPubKey(body.wallet, from_address, body.my_xpubkey, callbacks.ifOk);
				break;
```

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
