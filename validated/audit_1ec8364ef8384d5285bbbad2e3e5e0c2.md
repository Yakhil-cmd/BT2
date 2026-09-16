### Title
Plaintext device-message payloads (private keys, mnemonics, signatures, pairing secrets) are written to stdout logs - (File: `device.js`)

### Summary
`device.js` writes the full plaintext of every device-to-device message to `console.log`, both when sending (`reliablySendPreparedMessageToHub`) and when receiving/decrypting (`decryptPackage`). Device messages are the encrypted channel used for wallet cosigning, private-payment forwarding, textcoin mnemonics, pairing, and arbiter/prosaic contract data — all content that is supposed to be confidential end-to-end (hidden even from the hub). Logging it in cleartext on the node's stdout reproduces the same bug class as GHSA-c37v-3c8w-crq8 (zot printing OIDC `clientsecret` to stdout): sensitive secrets end up in operational logs where any process/log aggregator with read access to stdout can read them.

### Finding Description
Two logging statements in `device.js` leak the full plaintext JSON body of device messages:

- On send, before encryption: [1](#0-0) 
`reliablySendPreparedMessageToHub` logs `'will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json)` — the entire plaintext `json` object (which includes `subject` and `body`) is printed before it is ever encrypted.

- On receive, after decryption: [2](#0-1) 
`decryptPackage` logs `"decrypted: "+decrypted_message` — the full plaintext of every incoming device message, immediately after AES-GCM decryption and before any subject-specific validation is applied.

Device messages carry highly sensitive payloads reachable by any correspondent/paired device or trigger of the pairing/signing flow, e.g.:
- Multisig cosigning requests/responses containing raw ECDSA signatures and unsigned unit contents: [3](#0-2) 
- Private-payment chains forwarded to cosigners/recipients (blinding factors, amounts, addresses of private assets): [4](#0-3) 
- Pairing secrets exchanged in the `pairing` message body, including permanent pairing secrets used to authorize arbiter/prosaic contract counterparties: [5](#0-4) 
- Arbiter contract negotiation payloads, including `my_pairing_code` (`device_pubkey@hub#pairing_secret`) sent as part of contract offer/response/dispute/appeal messages: [6](#0-5) [7](#0-6) 

Because both logging calls fire unconditionally for *every* message sent or received — regardless of subject — any device that is paired with (or attempting to pair with) the node, any AA/wallet cosigner, or any counterparty in a private/arbiter/prosaic contract flow can trigger these code paths and force secret-bearing plaintext into the node operator's stdout logs.

### Impact Explanation
Logs are commonly collected, aggregated, retained, and sometimes shared with third parties (log shippers, monitoring dashboards, support tickets) with far weaker access controls than the wallet's own database or in-memory state. An attacker who obtains log access (a common lower-privilege foothold, e.g., via log-forwarding misconfiguration, shared hosting, or a compromised monitoring pipeline) could recover:
- Pairing secrets, enabling unauthorized pairing / social-engineering impersonation of the victim's device to correspondents.
- Cosigning signatures and unsigned unit contents for multisig wallets, potentially enabling forged or replayed signing flows against shared addresses.
- Private payment chain data (blinding factors/amounts) intended to be confidential to the recipient/cosigners only, defeating the purpose of Obyte's private-asset confidentiality model.

This does not directly cause double-spend or supply inflation, but it is a genuine confidentiality break of secrets that gate spending authorization (signatures, pairing codes) and privacy-sensitive payment data, reachable purely by normal protocol participants (paired devices, cosigners, contract counterparties) without any special privilege — matching the class of bug in the reference advisory (secrets printed to logs from unprivileged-reachable code paths).

### Likelihood Explanation
High reachability: these `console.log` calls execute on the hot path of every single device message sent or received by a node running with a console/terminal attached or with stdout redirected to a log file (a very common deployment pattern for hub-connected wallets/AA-integrated services). No attacker action is required beyond normal use of the pairing/signing/private-payment/arbiter-contract protocols, all of which are explicitly reachable by unprivileged correspondent devices per the threat model. The only precondition is that the victim node's stdout is persisted or exposed (e.g., piped to a log file, syslog, or container log driver) — a default assumption for most Node.js service deployments.

### Recommendation
Remove or gate these debug logging statements behind an explicit, disabled-by-default debug flag, and never log full plaintext message bodies:
- In `device.js` `reliablySendPreparedMessageToHub`, drop or redact `JSON.stringify(json)` from the log line (log only `subject` and `recipient_device_address`).
- In `device.js` `decryptPackage`, remove `console.log("decrypted: "+decrypted_message)` entirely, or replace it with a length-only or subject-only log line gated behind `conf.bLogDeviceMessages` (default `false`).
- Audit other `console.log` calls in `device.js`/`arbiter_contract.js` that print raw pairing codes, contract payloads, or key material, and apply the same redaction.

### Proof of Concept
1. Run a node with `console.log` output persisted to a file (default Node.js/PM2/systemd/docker logging behavior).
2. Have any correspondent device (or a device attempting first-time pairing) send a `pairing`, `sign`, or private-payment forwarding message to the node, as normal protocol usage — no special privilege needed.
3. Observe that `device.js`'s `decryptPackage` prints `"decrypted: " + decrypted_message` (full plaintext body, including pairing secret / signature / private payload data) to the node's log file, and that `reliablySendPreparedMessageToHub` similarly prints the full plaintext of every outgoing message the node itself sends.
4. Any party with read access to that log file (log aggregator, support staff, compromised monitoring agent) can extract pairing secrets, signatures, and private payment details from otherwise "encrypted" device-to-device traffic.

### Citations

**File:** device.js (L464-466)
```javascript
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
```

**File:** device.js (L570-573)
```javascript
function reliablySendPreparedMessageToHub(ws, recipient_device_pubkey, json, callbacks, conn){
	var recipient_device_address = objectHash.getDeviceAddress(recipient_device_pubkey);
	console.log('will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json));
	// encrypt to recipient's permanent pubkey before storing the message into outbox
```

**File:** device.js (L758-795)
```javascript
function sendPairingMessage(hub_host, recipient_device_pubkey, pairing_secret, reverse_pairing_secret, callbacks){
	var body = {pairing_secret: pairing_secret, device_name: my_device_name};
	if (reverse_pairing_secret)
		body.reverse_pairing_secret = reverse_pairing_secret;
	sendMessageToHub(hub_host, recipient_device_pubkey, "pairing", body, callbacks);
}

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

**File:** wallet.js (L251-317)
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
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (("messages" in objUnit) + ("signed_message" in objUnit) !== 1)
					return callbacks.ifError("either messages or signed_message must be present, but not both");
				if ("messages" in objUnit){
```

**File:** wallet.js (L2399-2437)
```javascript
					if (objAsset.is_private){
						var saveMnemonicsPreCommit = params.callbacks.preCommitCb;
						// save messages in outbox before committing
						params.callbacks.preCommitCb = function(conn, objJoint, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements, cb){
							if (!arrChainsOfRecipientPrivateElements || !arrChainsOfCosignerPrivateElements)
								throw Error('no private elements');
							var sendToRecipients = function(cb2){
								if (recipient_device_address) {
									walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
								} 
								else if (Object.keys(assocAddresses).length > 0) {
									var mnemonic = assocMnemonics[Object.keys(assocMnemonics)[0]]; // TODO: assuming only one textcoin here
									if (typeof opts.getPrivateAssetPayloadSavePath === "function") {
										opts.getPrivateAssetPayloadSavePath(function(fullPath, cordovaPathObj){
											if (!fullPath && (!cordovaPathObj || !cordovaPathObj.fileName)) {
												return cb2("no file path provided for storing private payload");
											}
											storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, function(err) {
												if (err)
													throw Error(err);
												saveMnemonicsPreCommit(conn, objJoint, cb2);
											});
										});
									} else {
										throw Error("no getPrivateAssetPayloadSavePath provided");
									}
								}
								else { // paying to another wallet on the same device
									forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChainsOfRecipientPrivateElements, false, conn, cb2);
								}
							};
							var sendToCosigners = function(cb2){
								if (wallet)
									walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChainsOfCosignerPrivateElements, [wallet], false, conn, cb2);
								else // arrPayingAddresses can be only shared addresses
									forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, null, false, conn, cb2);
							};
							async.series([sendToRecipients, sendToCosigners], cb);
						};
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

**File:** arbiter_contract.js (L262-296)
```javascript
function openDispute(hash, cb) {
	getByHash(hash, function(objContract){
		if (!["paid", "in_dispute"].includes(objContract.status))
			return cb("contract can't be disputed");
		device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, function(err, url){
			if (err)
				return cb(err);
			arbiters.getInfo(objContract.arbiter_address, async function(err, objArbiter) {
				if (err)
					return cb(err);
				err = await fillArbstoreAddresses(objContract);
				if (err)
					return cb(err);
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
```
