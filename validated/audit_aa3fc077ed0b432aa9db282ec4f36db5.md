### Title
Arbiter contract sharing leaks peer's/own permanent pairing secret (device-pairing credential) to cosigners without sanitization - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` shares the full arbiter-contract row — fetched with `SELECT *` — with cosigner devices without stripping the `my_pairing_code`/`peer_pairing_code` fields. These fields embed the raw permanent `pairing_secret` (`device_pubkey@hub#pairing_secret`) that `device.js` treats as sufficient proof to auto-pair a new "confirmed" correspondent device. This is the same bug class as GHSA-r67m-mf7v-qp7j: a response/shared object is not sanitized before being sent to a party who should not receive the embedded credential.

### Finding Description
`getByHash()` performs `SELECT * FROM wallet_arbiter_contracts WHERE hash=?` [1](#0-0)  and returns the raw row, including `my_pairing_code` and `peer_pairing_code`, which are stored verbatim as `device_pubkey@hub#pairing_secret` strings [2](#0-1) .

`shareContractToCosigners()` forwards this *entire unsanitized* `objContract` to every cosigner device of `my_address` (derived from `wallet_signing_paths`/`my_addresses`) via `device.sendMessageToDevice(..., "arbiter_contract_shared", objContract)`: [3](#0-2) 

Likewise, `shareUpdateToCosigners()`/`shareUpdateToPeer()` send `{hash, field, value: objContract[field]}`, and `field` is allowed to be `"peer_pairing_code"` per `setField`'s whitelist, so a targeted field-update message can also leak the raw pairing secret to cosigners: [4](#0-3) [5](#0-4) 

Notably, the code elsewhere *does* sanitize fields before sharing with a different audience — `createAndSend()` explicitly deletes `cosigners` before sending the offer to the peer (`delete objContractForPeer.cosigners;`) [6](#0-5)  — showing the developers are aware that objects must be pruned per-recipient, but they missed pruning `my_pairing_code`/`peer_pairing_code` before sharing with cosigners.

The leaked value is not cosmetic: `device.js`'s `handlePairingMessage()` treats presentation of a valid `pairing_secret` (matched against `pairing_secrets` table, and `is_permanent` secrets can be used by "multiple peers") as sufficient to add the presenter as a **confirmed correspondent device** with no further authentication: [7](#0-6) . A device's own permanent pairing secret is generated once and cached via `getOrGeneratePermanentPairingInfo()` [8](#0-7) , so leaking it is a durable credential compromise, not a one-time code.

### Impact Explanation
A cosigner is only supposed to be a partially-trusted party contributing a signature to a shared/multisig address in the arbiter-contract flow; it is not supposed to learn the counterparty's (or the offeror's) permanent device-pairing secret. Once an untrusted cosigner obtains this secret (via `arbiter_contract_shared` or `arbiter_contract_update` messages), it can pair with that device as a new "confirmed" correspondent and subsequently exchange messages that are normally reserved for trusted paired devices (e.g. `sign` offers, `private_payments`, `text`, wallet/contract negotiation messages). This enables social-engineering or spoofing attacks against the wallet's contract/message-handling flow (e.g., impersonating the peer to send crafted signing requests or dispute-related messages), which can lead to unauthorized fund-movement approvals or leakage of further private-payment/wallet data — consistent with the CWE-200/CWE-116 sensitive-data-disclosure class of the referenced advisory, mapped onto ocore's wallet/device pairing model.

### Likelihood Explanation
Likelihood is moderate: it requires the victim to have set up a cosigner-based (multisig) `my_address` in an arbiter contract, and for that cosigner to be less trusted than assumed (e.g., a compromised or borrowed device, or a cosigner added by a non-owner). Given the arbiter-contract feature is specifically designed to support multiple cosigners on one side of a contract, this is a realistic configuration reachable purely from normal wallet/contract usage — no p2p/hub compromise or malicious node is required.

### Recommendation
Before calling `device.sendMessageToDevice(..., "arbiter_contract_shared"/"arbiter_contract_update", ...)` to cosigners, strip `my_pairing_code` and `peer_pairing_code` (and any other credential-bearing fields) from the object, mirroring the existing sanitization already done for `cosigners` in `createAndSend()`. Additionally, remove `"peer_pairing_code"`/`my_pairing_code` from the set of fields eligible for cosigner-facing `shareUpdateToCosigners` propagation, or replace the raw pairing secret with a non-sensitive placeholder when broadcasting to cosigners.

### Proof of Concept
1. Alice creates/accepts an arbiter contract with Bob, using a multisig `my_address` that includes Carol as a cosigner (`wallet_signing_paths`).
2. When Alice accepts the contract, `respond()` sets/stores `my_pairing_code` (Alice's permanent pairing secret) and, upon acceptance, calls `shareContractToCosigners(hash)` [9](#0-8)  which sends the full `objContract` (including `my_pairing_code` and, once received, `peer_pairing_code`) to Carol's device.
3. Carol extracts `peer_pairing_code`/`my_pairing_code` from the received `arbiter_contract_shared`/`arbiter_contract_update` message and uses it to send a `pairing` justsaying message to Bob's (or Alice's) hub with that `pairing_secret`.
4. `handlePairingMessage()` on the target device accepts Carol as a newly confirmed correspondent device without any further verification [10](#0-9) , granting Carol trusted-correspondent status she was never supposed to have.

### Citations

**File:** arbiter_contract.js (L21-34)
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
```

**File:** arbiter_contract.js (L38-46)
```javascript
function getByHash(hash, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE hash=?", [hash], function(rows){
		if (!rows.length) {
			return cb(null);
		}
		var contract = rows[0];
		cb(decodeRow(contract));			
	});
}
```

**File:** arbiter_contract.js (L133-138)
```javascript
			setField(objContract.hash, "status", status, function(objContract) {
				if (status === "accepted") {
					shareContractToCosigners(objContract.hash);
				};
				cb(null, objContract);
			});
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

**File:** arbiter_contract.js (L168-176)
```javascript
function shareContractToCosigners(hash) {
	getByHash(hash, function(objContract){
		getAllMyCosigners(hash, function(cosigners) {
			cosigners.forEach(function(device_address) {
				device.sendMessageToDevice(device_address, "arbiter_contract_shared", objContract);
			});
		});
	});
}
```

**File:** arbiter_contract.js (L178-192)
```javascript
function shareUpdateToCosigners(hash, field) {
	getByHash(hash, function(objContract){
		getAllMyCosigners(hash, function(cosigners) {
			cosigners.forEach(function(device_address) {
				device.sendMessageToDevice(device_address, "arbiter_contract_update", {hash: objContract.hash, field: field, value: objContract[field]});
			});
		});
	});
}

function shareUpdateToPeer(hash, field) {
	getByHash(hash, function(objContract){
		device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_update", {hash: objContract.hash, field: field, value: objContract[field]});
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

**File:** device.js (L797-847)
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
```
