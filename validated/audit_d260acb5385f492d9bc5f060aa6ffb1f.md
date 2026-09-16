### Title
Permanent device-pairing secret is embedded in outbound HTTP/hub payloads, letting a low-trust arbiter-contract counterparty or arbstore server permanently self-pair as a correspondent device - (File: [arbiter_contract.js](arbiter_contract.js))

### Summary
`device.getOrGeneratePermanentPairingInfo()` creates (once) and forever reuses a single `is_permanent=1` pairing secret that never expires until `2038-01-01` [1](#0-0) . `arbiter_contract.js` repeatedly composes this permanent secret into `my_pairing_code` and pushes it out to two parties that do not need standing pairing rights: the contract counterparty (`respond()`) and the external arbstore HTTP service (`openDispute()`, `appeal()`) [2](#0-1) [3](#0-2) [4](#0-3) . This is the ocore analog of the OpenMetadata bug: a highly-privileged, non-scoped, non-rotating credential ("JWT"-equivalent) is included in ordinary business-flow payloads visible to parties whose role should not require it.

### Finding Description
The permanent pairing secret is meant to be a user-controlled "invite/QR" credential; anyone who redeems it via `hub/deliver`→`handlePairingMessage()` is immediately added and auto-`is_confirmed=1` as a `correspondent_devices` entry, with no further approval step [5](#0-4) . In `arbiter_contract.js`:
- `respond()` sends `my_pairing_code` (built from the permanent secret) to `objContract.peer_device_address` whenever a contract is accepted [2](#0-1) .
- `openDispute()` serializes `my_pairing_code`/`peer_pairing_code` into a JSON payload POSTed to the arbstore's `/api/dispute/new` HTTP endpoint [6](#0-5) .
- `appeal()` does the same for `/api/appeal/new` [7](#0-6) .

Because `getOrGeneratePermanentPairingInfo()` always returns the *same* stored secret rather than a fresh, single-use one, every contract, every dispute, and every appeal re-exposes the identical long-lived credential to a different external party (arbstore operators, contract counterparties) [1](#0-0) . Any party that captures it (a malicious/compromised arbstore server, a network observer of the arbstore HTTP call, or simply a counterparty who is not supposed to retain standing access) can redeem it at any later time to permanently register a new device as a trusted, `is_confirmed` correspondent of the victim's wallet — indistinguishable from a device the user genuinely invited.

### Impact Explanation
A silently-added "confirmed" correspondent device can subsequently reach several wallet message handlers that display content to the user or drive multi-party flows without further pairing checks, e.g. `case "text"`/`case "object"` (rendered to the user, usable for phishing/social engineering to get a payment or contract signed) [8](#0-7) , and `create_new_shared_address` / `arbiter_contract_offer` flows that only require the sender's `from_address` be a legitimate correspondent, not that the user explicitly invited them for that purpose [9](#0-8) . Since the leaked secret is never rotated, a single exposure (e.g. one compromised or malicious arbstore) grants indefinite (until 2038) re-poseability as a trusted correspondent of the victim's wallet, materially increasing the attack surface for social-engineering-driven unauthorized fund transfers, matching the "user impersonation leading to destructive outcomes" impact class described in the source report.

### Likelihood Explanation
No attacker interaction with core validation logic is required — simply operating (or compromising) an arbstore server, or being a one-time arbiter-contract counterparty, is enough to permanently capture the secret through completely legitimate application flows (`openDispute`, `appeal`, `respond`). The secret is transmitted routinely (every dispute/appeal/accepted contract), so exposure surface accumulates over time.

### Recommendation
- Stop reusing the single permanent pairing secret across all outbound flows; generate a short-lived, single-use pairing secret (`startWaitingForPairing()` already exists for this purpose) scoped specifically to the arbstore or counterparty interaction that needs it [10](#0-9) .
- Do not include `my_pairing_code`/permanent pairing secrets in the `/api/dispute/new` and `/api/appeal/new` payloads sent to arbstore unless strictly required, and if required, use ephemeral secrets tied to that dispute only.
- Consider requiring explicit user confirmation before any newly-paired correspondent (even via a valid secret) is granted `is_confirmed=1`, rather than auto-confirming in `handlePairingMessage()`.

### Proof of Concept
1. User A creates and accepts an arbiter contract; `respond()` sends `my_pairing_code` (permanent secret) to the peer device [2](#0-1) .
2. User A later opens a dispute; `openDispute()` POSTs the same permanent `my_pairing_code` to the arbstore's `/api/dispute/new` endpoint [6](#0-5) .
3. A malicious/compromised arbstore operator (or anyone who captured the HTTP payload) extracts `device_pubkey@hub#pairing_secret` from the JSON body.
4. At any later time, the attacker sends a `pairing` message using this secret to User A's hub; `handlePairingMessage()` accepts it and marks the attacker's device as `is_confirmed=1` correspondent, with no additional check that this is the originally-intended relationship [5](#0-4) .
5. The attacker's now-trusted device can send `text`/contract-offer messages that are rendered to User A, or drive shared-address/multisig setup requests that trigger confirmation dialogs — enabling social-engineering-based fund loss, entirely because a supposedly narrow-purpose interaction (dispute/appeal submission) exposed a full-privilege, non-rotating pairing credential.

### Citations

**File:** device.js (L765-776)
```javascript
function startWaitingForPairing(handlePairingInfo){
	var pairing_secret = crypto.randomBytes(9).toString("base64");
	var pairingInfo = {
		pairing_secret: pairing_secret,
		device_pubkey: objMyPermanentDeviceKey.pub_b64,
		device_address: my_device_address,
		hub: my_device_hub
	};
	db.query("INSERT INTO pairing_secrets (pairing_secret, expiry_date) VALUES(?, "+db.addTime("+1 MONTH")+")", [pairing_secret], function(){
		handlePairingInfo(pairingInfo);
	});
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

**File:** device.js (L816-847)
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

**File:** arbiter_contract.js (L140-150)
```javascript
		if (status === "accepted") {
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				setField(objContract.hash, "my_pairing_code", pairing_code);
				composer.composeAuthorsAndMciForAddresses(db, [objContract.my_address], signer, function(err, authors) {
					if (err) {
						return cb(err);
					}
					send(authors, pairing_code);
				});
			});
```

**File:** arbiter_contract.js (L275-303)
```javascript
				device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
					var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
					var data = {
						contract_hash: hash,
						unit: objContract.unit,
						my_address: objContract.my_address,
						peer_address: objContract.peer_address,
						me_is_payer: objContract.me_is_payer,
						my_pairing_code: objContract.my_pairing_code,
						peer_pairing_code: objContract.peer_pairing_code,
						encrypted_contract: device.createEncryptedPackage({
							title: objContract.title,
							text: objContract.text,
							creation_date: objContract.creation_date,
							plaintiff_party_name: objContract.my_party_name,
							respondent_party_name: objContract.peer_party_name,
							my_contact_info: objContract.my_contact_info,
							peer_contact_info: objContract.peer_contact_info,
						}, objArbiter.device_pub_key),
						my_contact_info: objContract.my_contact_info,
						peer_contact_info: objContract.peer_contact_info
					};
					db.query("SELECT 1 FROM assets WHERE unit IN(?) AND is_private=1 LIMIT 1", [objContract.asset], function(rows){
						if (rows.length > 0) {
							data.asset = objContract.asset;
							data.amount = objContract.amount;
						}
						var dataJSON = JSON.stringify(data);
						httpRequest(url, "/api/dispute/new", dataJSON, function(err, resp) {
```

**File:** arbiter_contract.js (L337-345)
```javascript
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				var data = JSON.stringify({
					contract_hash: hash,
					my_pairing_code: objContract.my_pairing_code,
					my_address: objContract.my_address,
					contract: {title: objContract.title, text: objContract.text, creation_date: objContract.creation_date, me_is_payer: objContract.me_is_payer, my_address: objContract.my_address, peer_address: objContract.peer_address, my_party_name: objContract.my_party_name, peer_party_name: objContract.peer_party_name, arbiter_address: objContract.arbiter_address, amount: objContract.amount, asset: objContract.asset},
				});
				httpRequest(url, "/api/appeal/new", data, function(err, resp) {
```

**File:** wallet.js (L101-122)
```javascript
			case "text":
				message_counter++;
				if (!ValidationUtils.isNonemptyString(body))
					return callbacks.ifError("text body must be string");
				body = body
					.replace(/\(prosaic-contract:.+?\)/g, '')
					.replace(/\(arbiter-contract-offer:.+?\)/g, '')
					.replace(/\(arbiter-contract-event:.+?\)/g, '')
					.replace(/\(arbiter-dispute:.+?\)/g, '');
				// the wallet should have an event handler that displays the text to the user
				eventBus.emit("text", from_address, body, message_counter);
				callbacks.ifOk();
				break;

			case "object":
				message_counter++;
				if(typeof body !== 'object')
					return callbacks.ifError("body must be object");

				eventBus.emit("object", from_address, body, message_counter);
				callbacks.ifOk();
				break;
```

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
```
