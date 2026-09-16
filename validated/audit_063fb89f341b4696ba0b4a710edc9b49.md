### Title
Permanent device pairing secret stored and transmitted in plaintext via arbiter contracts, enabling correspondent-device impersonation - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` embeds the wallet's **permanent** pairing secret (`pairing_secret`, valid until year 2038, reusable by unlimited peers) inside the `my_pairing_code` field of every arbiter contract offer/response, stores it unencrypted in the local `wallet_arbiter_contracts` table, forwards it in plaintext to the contract counterparty over the device-messaging channel, re-shares it with every cosigner of the contract, and again transmits it in a plain JSON payload to an external `arbstore` HTTP endpoint during dispute appeals. This mirrors the Rancher bug class: a long-lived, reusable authentication secret is persisted and exposed in plaintext to parties/objects that should not need to hold it, instead of being minted per-recipient or short-lived.

### Finding Description
`device.getOrGeneratePermanentPairingInfo()` lazily creates (or reuses) a single **permanent** `pairing_secret` per wallet instance and stores it in the `pairing_secrets` table with `is_permanent=1` and an expiry of `2038-01-01`: [1](#0-0) 

This permanent secret is the credential later validated in `handlePairingMessage`, and because it is permanent, "multiple peers can pair through permanent secret": [2](#0-1) 

`arbiter_contract.js` retrieves this same permanent secret and concatenates it into `my_pairing_code`, then:
1. Persists it in plaintext in the `wallet_arbiter_contracts` table on contract creation.
2. Sends it unencrypted to `objContract.peer_device_address` — a party that is, at contract-offer time, merely an untrusted counterparty, not yet a vetted correspondent.
3. Re-sends it to `objContract.peer_device_address` again on `respond()`, and shares it further with cosigners via `shareContractToCosigners`.
4. Sends it a third time, embedded in a plain JSON body, to an external `arbstore` HTTPS endpoint during `appeal()`. [3](#0-2) [4](#0-3) [5](#0-4) 

Because the pairing secret is permanent and shared across *every* contract and *every* cosigner rather than being minted fresh and single-use per counterparty, any party that ever transacts an arbiter contract with a user (an unprivileged, self-selected counterparty — anyone can send an `arbiter_contract_offer`) permanently learns the credential needed to re-pair as a "confirmed" correspondent device of that user at any future time, via `handlePairingMessage`, which unconditionally marks the pairer `is_confirmed=1` once it presents the correct `pairing_secret`: [6](#0-5) 

### Impact Explanation
Once an attacker (a mere arbiter-contract counterparty) learns the victim's permanent pairing secret, they can re-pair with the victim as a trusted, confirmed correspondent device at will, without the victim's explicit out-of-band consent (which is the normal, intended security boundary for adding a correspondent). A confirmed correspondent is subsequently treated as a legitimate device peer for downstream flows such as multi-signature wallet setup (`wallet_defined_by_keys.js`), textcoin/private-payment notifications, and other device-message-driven wallet operations that are processed with reduced scrutiny ("silently", "without user interaction", per code comments). This creates a realistic path to social-engineering-free device impersonation that can be leveraged to inject fraudulent shared-address cosigner data or intercept private payment/AA-related device messages intended for the legitimate correspondent, ultimately risking fund loss for the victim.

### Likelihood Explanation
Likelihood is high for the exposure step itself: any user who is offered or responds to an arbiter contract, or who appeals a dispute, automatically leaks their permanent pairing secret to the counterparty (and cosigners, and the arbstore server) as a normal part of the existing code flow — no attacker action beyond initiating/participating in a contract is required. This is a single-posted-message-reachable action (arbiter contract offer/response) available to any unprivileged peer.

### Recommendation
- Never reuse a single permanent pairing secret across multiple untrusted counterparties; generate a short-lived, single-use pairing token per arbiter contract interaction, scoped only to that contract and expiring after use.
- Do not persist `my_pairing_code`/`pairing_secret` in plaintext in `wallet_arbiter_contracts`; if pairing information must be retained, encrypt it at rest or, better, avoid embedding the wallet's permanent pairing secret in contract objects altogether.
- Do not transmit the permanent pairing secret to third-party HTTP services (`arbstore`) during `appeal()`.
- Require explicit user confirmation before `handlePairingMessage` marks a new device as `is_confirmed=1` when the pairing secret used was one distributed automatically via contract flows rather than out-of-band (e.g., QR code).

### Proof of Concept
1. Attacker sends the victim an arbiter contract offer (`arbiter_contract_offer`), or accepts one such that `respond()` executes with `status === "accepted"`.
2. In both `createAndSend` and `respond`, the victim's client calls `device.getOrGeneratePermanentPairingInfo()` and builds `my_pairing_code = device_pubkey + "@" + hub + "#" + pairing_secret`, sending it directly to the attacker's `peer_device_address` in plaintext via `device.sendMessageToDevice`. [7](#0-6) 
3. Attacker now possesses the victim's permanent `pairing_secret`.
4. At any later time, the attacker sends a `pairing` message to the victim's hub using the captured `pairing_secret`; `handlePairingMessage` accepts it (since it is permanent and not yet expired) and inserts/confirms the attacker's device as a legitimate correspondent: [8](#0-7) 
5. The attacker is now a confirmed correspondent device of the victim and can participate in subsequent wallet/device-message flows as a trusted peer.

### Citations

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

**File:** arbiter_contract.js (L21-35)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
	device.getOrGeneratePermanentPairingInfo(pairingInfo => {
		objContract.my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
		db.query("INSERT INTO wallet_arbiter_contracts (hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, my_contact_info, my_pairing_code, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 0, objContract.creation_date, objContract.ttl, status_PENDING, objContract.title, objContract.text, objContract.my_contact_info, objContract.my_pairing_code, JSON.stringify(objContract.cosigners) ... (truncated)
				var objContractForPeer = _.cloneDeep(objContract);
				delete objContractForPeer.cosigners;
				device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_offer", objContractForPeer);
				if (cb) {
					cb(objContract);
				}
		});
	});
```

**File:** arbiter_contract.js (L118-150)
```javascript
function respond(hash, status, signedMessageBase64, signer, cb) {
	cb = cb || function(){};
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending" && objContract.status !== "accepted")
			return cb("contract is in non-applicable status");
		var send = function(authors, pairing_code) {
			var response = {hash: objContract.hash, status: status, signed_message: signedMessageBase64, my_contact_info: objContract.my_contact_info};
			if (authors) {
				response.authors = authors;
			}
			if (pairing_code) {
				response.my_pairing_code = pairing_code;
			}
			device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_response", response);

			setField(objContract.hash, "status", status, function(objContract) {
				if (status === "accepted") {
					shareContractToCosigners(objContract.hash);
				};
				cb(null, objContract);
			});
		};
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

**File:** arbiter_contract.js (L321-353)
```javascript
function appeal(hash, cb) {
	getByHash(hash, function(objContract){
		if (objContract.status !== "dispute_resolved")
			return cb("contract can't be appealed");
		var command = "hub/get_arbstore_url";
		var address = objContract.arbiter_address;
		if (objContract.arbstore_address) {
			command = "hub/get_arbstore_url_by_address";
			address = objContract.arbstore_address;
		}
		device.requestFromHub(command, address, async function(err, url){
			if (err)
				return cb("can't get arbstore url:", err);
			err = await fillArbstoreAddresses(objContract);
			if (err)
				return cb(err);
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				var data = JSON.stringify({
					contract_hash: hash,
					my_pairing_code: objContract.my_pairing_code,
					my_address: objContract.my_address,
					contract: {title: objContract.title, text: objContract.text, creation_date: objContract.creation_date, me_is_payer: objContract.me_is_payer, my_address: objContract.my_address, peer_address: objContract.peer_address, my_party_name: objContract.my_party_name, peer_party_name: objContract.peer_party_name, arbiter_address: objContract.arbiter_address, amount: objContract.amount, asset: objContract.asset},
				});
				httpRequest(url, "/api/appeal/new", data, function(err, resp) {
					if (err)
						return cb(err);
					setField(hash, "status", "in_appeal", function(objContract) {
						cb(null, resp, objContract);
					});
				});
			});
		});
```
