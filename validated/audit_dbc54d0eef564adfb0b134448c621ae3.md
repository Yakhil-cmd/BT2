## Analysis

The buildkit bug class is: **a secret/credential gets embedded inline into a URL-like string, and that string is later forwarded, unredacted, to a third party who was never meant to see the secret** (in buildkit's case, the git URL credentials end up in the provenance attestation seen by anyone with attestation access).

The direct analog in `ocore--008` is in the arbiter-contract flow (`arbiter_contract.js`), which is exactly the kind of "private-payment counterparty" / "contract message handling" surface the scope allows.

### Root cause

`device.getOrGeneratePermanentPairingInfo()` returns the wallet's **permanent** device-pairing secret (created once, valid until 2038), which is concatenated into a pairing-code string `pubkey@hub#pairing_secret`: [1](#0-0) 

Knowledge of that string alone lets anyone become a fully confirmed correspondent device (`handlePairingMessage` inserts them into `correspondent_devices` with `is_confirmed=1` on presentation of the secret, no other authorization needed): [2](#0-1) 

This `my_pairing_code` is legitimately embedded once, when creating/accepting a contract, so that the *direct counterparty* can pair back: [3](#0-2) [4](#0-3) 

However, both `my_pairing_code` **and** `peer_pairing_code` (i.e. the counterparty's permanent pairing secret too) are subsequently forwarded, unmodified, to two additional parties that were never party to the pairing exchange:

1. **The Arbstore server** (a semi-trusted, network-reachable HTTP service run by the arbiter), inside `openDispute()` and `appeal()`: [5](#0-4) [6](#0-5) 

2. **All wallet cosigners**, via `shareContractToCosigners`, which ships the entire `objContract` row (including both pairing codes) as a device message: [7](#0-6) 

## #Title
Permanent device-pairing secrets embedded in arbiter-contract pairing codes are leaked to the Arbstore server and to cosigners - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` embeds each party's **permanent** device pairing secret into a `pubkey@hub#pairing_secret` "pairing code" string, analogous to embedding credentials in a URL. This pairing code is stored on the contract object and is then forwarded, unredacted, to third parties who never participated in the original pairing exchange: the Arbstore HTTP service (`openDispute`, `appeal`) and every cosigner of the shared wallet (`shareContractToCosigners`).

### Finding Description
`createAndSend()` and `respond()` generate `my_pairing_code` from `device.getOrGeneratePermanentPairingInfo()`, which is the wallet's long-lived (2038 expiry) pairing secret [8](#0-7) . This secret is meant only to let the direct contract counterparty pair back with the device.

Both `my_pairing_code` and (once received) `peer_pairing_code` are persisted on the `wallet_arbiter_contracts` row and are then embedded into the JSON payload POSTed to the Arbstore server when opening a dispute or filing an appeal [9](#0-8) [10](#0-9) , and are also included in the full contract object broadcast to every cosigner device via `shareContractToCosigners()` [7](#0-6) .

Because `handlePairingMessage()` authorizes *any* sender who can present the secret as a confirmed correspondent, without further checks tied to the original contract context [11](#0-10) , possession of a leaked pairing code is sufficient to become a trusted device correspondent of the victim's wallet.

### Impact Explanation
An Arbstore operator (only semi-trusted — it is meant to see dispute contract content, not act as a wallet correspondent) or any cosigner of a shared/multisig wallet can extract the plaintext permanent pairing secret of **both** contract parties from data they legitimately receive for a different purpose. With that secret they can pair as a confirmed correspondent device of the victim wallet and subsequently:
- Receive private-payment chain messages/chunks intended for legitimate correspondents (private payment history/asset transfer disclosure).
- Send crafted co-signing requests for multisig/shared addresses (`wallet_defined_by_addresses.js` signing flow) that a user may approve believing they originate from an already-trusted device, potentially leading to unauthorized spending from shared addresses used by the arbiter-contract escrow.

This matches the CWE-200 / credential-leak class of the reference advisory, applied to the ocore device-pairing trust model instead of Git.

### Likelihood Explanation
Every arbiter contract dispute or appeal (`openDispute`/`appeal`) unconditionally sends both pairing codes to the Arbstore server, and every `accepted` contract is unconditionally shared with all cosigners including the pairing codes — no opt-out or secret redaction exists. The attack requires the Arbstore operator (or a malicious cosigner) to act on the leaked secret and for the wallet UI to accept the resulting pairing/signing request (comparable to `UI:R` in the original CVSS vector), but no special privilege beyond running/administering the Arbstore or being a cosigner is needed.

### Recommendation
- Never place `my_pairing_code`/`peer_pairing_code` (or the raw `pairing_secret`) inside payloads sent to the Arbstore server; the Arbstore only needs the dispute content, not a means to pair with either party's wallet. Strip these fields in `openDispute`/`appeal` before building `data`.
- Do not forward `my_pairing_code`/`peer_pairing_code` to cosigners in `shareContractToCosigners`; strip them from the object cloned/sent, similar to how `cosigners` itself is already deleted before sending to the peer in `createAndSend` (`delete objContractForPeer.cosigners`).
- Consider generating a short-lived, dispute-scoped pairing secret instead of reusing the wallet's permanent pairing secret for any communication that leaves the direct peer relationship.

### Proof of Concept
1. Alice and Bob create and accept an arbiter contract; both `my_pairing_code`/`peer_pairing_code` (permanent pairing secrets) are stored on the contract row.
2. Alice opens a dispute: `openDispute()` POSTs `{ ..., my_pairing_code: <Alice secret>, peer_pairing_code: <Bob secret>, ... }` to the Arbstore's `/api/dispute/new` endpoint [12](#0-11) .
3. The Arbstore operator extracts `peer_pairing_code`, parses `pubkey@hub#pairing_secret`, and sends a `pairing` message to Bob's hub using that secret.
4. `handlePairingMessage()` on Bob's device confirms the Arbstore as a legitimate correspondent device with no further verification [11](#0-10) .
5. The Arbstore can now exchange arbitrary device messages with Bob's wallet as a trusted correspondent (e.g., private payment chunks, or multisig co-signing requests presented to Bob's UI).

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

**File:** device.js (L798-826)
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
```

**File:** arbiter_contract.js (L21-36)
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
}
```

**File:** arbiter_contract.js (L118-155)
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
		} else {
			send();
		}
	});
}
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
