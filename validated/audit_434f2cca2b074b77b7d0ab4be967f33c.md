### Title
Arbiter contract disclosure of counterparty pairing secrets to all cosigners of a shared-address wallet - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` implements a peer-to-peer/arbitrated contract feature layered on top of ocore's shared-address (multisig) wallets. When a multisig account participates in an arbiter contract, the contract record (which contains `my_pairing_code` and `peer_pairing_code` — literal device-pairing secrets in the form `pubkey@hub#pairing_secret`) is broadcast in full to every co-signer device of the wallet via `shareContractToCosigners`, without stripping these secrets the way `createAndSend` deliberately strips `cosigners` before sending the contract to the counterparty.

### Finding Description
`shareContractToCosigners` reads the complete contract row via `getByHash` and forwards it verbatim to every device returned by `getAllMyCosigners`: [1](#0-0) 

`getAllMyCosigners` simply enumerates every device address associated with the wallet-signing-paths of `my_address` (i.e., every co-signer of the local multisig/shared wallet), with no filtering by role or trust level: [2](#0-1) 

The object being shared includes `my_pairing_code` and, once received from the peer, `peer_pairing_code` — both are full pairing codes of the form `device_pubkey@hub#pairing_secret`, as constructed in `respond()` and `openDispute()`/`appeal()`: [3](#0-2) [4](#0-3) 

A pairing secret is a bearer credential: whoever presents it to the hub via `handlePairingMessage` is added as a trusted correspondent of that device and can then exchange authenticated device messages with it — the exact mechanism used elsewhere for signing requests, private-payment forwarding, and wallet approval flows: [5](#0-4) 

By contrast, when the contract is first sent to the direct counterparty in `createAndSend`, the developer explicitly stripped the `cosigners` array before transmission, showing that not all contract fields are meant to be exposed to every party that touches the contract: [6](#0-5) 

No equivalent stripping happens in `shareContractToCosigners`, `store()` (used when a cosigner receives and persists the shared contract), or in the `respond`/`createSharedAddressAndPostUnit` code paths that invoke it, so a cosigner who is only supposed to help co-sign the shared multisig payment address also receives the plaintext pairing secrets belonging to the counterparty and the contract owner.

This mirrors the structure of CVE-2025-26521: a resource meant to be shared among a limited group for one purpose (co-signing a payment address / running a CKS cluster) inadvertently discloses a bearer credential (pairing secret / cloudstack API-secret key) belonging to another party, enabling the recipient to impersonate that party outside the intended scope.

### Impact Explanation
A cosigner is just one signer among several in a shared multisig address; being a cosigner does not imply the counterparty or the arbiter should trust that device directly. Obtaining `peer_pairing_code`/`my_pairing_code` lets a malicious cosigner pair as a correspondent with the counterparty's device (or the contract-initiating device) without their consent, then use device messaging (signing requests, private-payment chain forwarding, contact info exchange, dispute data) to attempt social-engineering, phishing, or protocol-level requests that the real correspondent would not expect from an unknown device. Given ocore's device-messaging model treats a known correspondent as a trusted channel for cooperative signing (`wallet.js` `sign`/`ifRemote` flow) and private-chain forwarding, this could be leveraged toward tricking a party into signing malicious payments or leaking further private-asset transfer data through spoofed but "paired" correspondence — a fund-loss/impersonation risk analogous to the CloudStack finding, though it requires additional social-engineering/protocol misuse rather than instant fund theft, hence rated high rather than critical.

### Likelihood Explanation
Exploitation only requires being an ordinary cosigner of a multisig wallet that also participates in an arbiter contract — a role reachable by any legitimate but potentially malicious co-owner of a shared wallet, with no special privilege beyond what's already granted to run `shareContractToCosigners`/`shareUpdateToCosigners` (triggered automatically on `respond()` acceptance and on `createSharedAddressAndPostUnit`). No hub or network compromise is needed; the leak occurs in the normal application-level device-message flow.

### Recommendation
Strip `my_pairing_code`/`peer_pairing_code` (and any other bearer secrets) from the object passed to `shareContractToCosigners`/`shareUpdateToCosigners`, mirroring the `delete objContractForPeer.cosigners` pattern already used in `createAndSend`. Cosigners should only receive the fields necessary to construct/verify the shared address and co-sign transactions (e.g., `hash`, `title`, `amount`, `asset`, `arbiter_address`, `shared_address`), not pairing credentials belonging to other parties.

### Proof of Concept
1. Device A creates a multisig wallet shared with cosigner device C (via `wallet_defined_by_addresses.createNewSharedAddress`), and uses `my_address` (a member of that shared wallet) to open an arbiter contract with peer device B (`arbiter_contract.createAndSend`).
2. B accepts via `respond(hash, "accepted", ...)`, causing B's device to generate and send `my_pairing_code` to A, and A's own `my_pairing_code` was likewise generated at contract creation. Both values are persisted into `wallet_arbiter_contracts.my_pairing_code`/`peer_pairing_code` on A's node. [7](#0-6) 
3. After acceptance, `shareContractToCosigners(hash)` is invoked, which loads the full contract row (including both pairing codes) and sends it as `arbiter_contract_shared` to every device address in `getAllMyCosigners(hash)` — including cosigner C, who has no direct business relationship with B. [1](#0-0) [2](#0-1) 
4. Cosigner C now possesses B's `peer_pairing_code` (`device_pubkey@hub#pairing_secret`) and can use it via the standard pairing URI/`handlePairingMessage` flow to become a correspondent of B without B's knowledge, then attempt to interact with B's device as a "known" correspondent. [5](#0-4)

### Citations

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

**File:** arbiter_contract.js (L275-284)
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
```

**File:** arbiter_contract.js (L440-452)
```javascript
function getAllMyCosigners(hash, cb) {
	db.query("SELECT device_address FROM wallet_signing_paths \n\
		JOIN my_addresses AS ma USING(wallet)\n\
		JOIN wallet_arbiter_contracts AS wac ON wac.my_address=ma.address\n\
		WHERE wac.hash=?", [hash], function(rows) {
			var cosigners = [];
			rows.forEach(function(row) {
				if (row.device_address !== device.getMyDeviceAddress())
					cosigners.push(row.device_address);
			});
			cb(cosigners);
		});
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
