### Title
Information disclosure of contract counterparties' private contact info to the arbstore server in `openDispute` - (File: arbiter_contract.js)

### Summary
When a wallet user opens an arbitration dispute for an already-paid arbiter contract, `arbiter_contract.js`'s `openDispute()` sends both parties' `my_contact_info` and `peer_contact_info` to the arbstore server in cleartext, even though the code simultaneously encrypts the very same fields specifically for the arbiter's device key. This defeats the confidentiality protection that encryption was meant to provide and exposes personally identifying contact information of both the disputing user and the (possibly non-consenting) counterparty to the arbstore operator, which is architecturally a separate, less-trusted party from the arbiter.

### Finding Description
`openDispute()` builds the payload sent to the arbstore's `/api/dispute/new` endpoint: [1](#0-0) 

The `encrypted_contract` field is explicitly end-to-end encrypted to `objArbiter.device_pub_key` via `device.createEncryptedPackage(...)`, and it includes `my_contact_info` and `peer_contact_info` among its encrypted fields, indicating the intent that this PII should only be readable by the arbiter's device. However, immediately below, the *same* `my_contact_info` and `peer_contact_info` values are also placed in the top-level, unencrypted `data` object that is JSON-serialized and POSTed as plaintext over HTTPS directly to the arbstore host: [2](#0-1) 

The arbstore is a distinct network entity from the arbiter — it merely relays/hosts the dispute API and takes a fee cut (`arbstoreInfo.cut`), as seen in `deriveSharedAddress()`'s shared-address definition construction and the `arbstore_address`/`arbstore_device_address` handling in `fillArbstoreAddresses()`/`getArbstoreAddresses()`. The arbstore never receives the arbiter's decryption key, so the encryption of `encrypted_contract` is specifically meant to keep the arbstore blind to sensitive contract content (title, text, party names, contact info) while still allowing it to route the dispute to the arbiter.

That the redundant plaintext contact-info fields are a genuine oversight (not intended design) is corroborated by the sibling `appeal()` function, which packages contract data for the very same arbstore endpoint category but deliberately omits `my_contact_info`/`peer_contact_info` from its plaintext `contract` object: [3](#0-2) 

This asymmetry shows that `openDispute()` is leaking data that the analogous `appeal()` path correctly keeps out of the unencrypted payload.

### Impact Explanation
Any wallet user who is a party to a paid arbiter contract (an unprivileged, standard wallet operation) can trigger `openDispute()`. Doing so unilaterally discloses the counterparty's private contact information (`peer_contact_info` — typically containing PII such as name, email, or phone used for dispute-resolution) to the arbstore server in plaintext, without the counterparty's consent and contrary to the app's own confidentiality model (as evidenced by the parallel encryption to the arbiter's key). This is a genuine confidentiality breach of user data to a third-party service operator who is not supposed to be able to read it, matching the "information disclosure" bug class of the external report, scoped to `ocore`'s wallet/contract message handling path.

### Likelihood Explanation
High likelihood of occurrence: opening a dispute is a normal, user-reachable action available to any payer or payee of a signed/paid arbiter contract (`objContract.status` in `["paid", "in_dispute"]`), requiring no special privilege, malicious peer, or network position — it is triggered purely by the disputing party's own wallet code path in `arbiter_contract.js`.

### Recommendation
Remove the redundant plaintext `my_contact_info` and `peer_contact_info` fields from the top-level `data` object sent to `/api/dispute/new` in `openDispute()`, relying solely on `encrypted_contract` (as `appeal()` already does), so that contact information is only ever exposed to the arbiter's device via its own decryption key, not to the arbstore relay.

### Proof of Concept
1. Alice and Bob complete and pay an arbiter contract (`status = "paid"`).
2. Alice (or Bob) calls `arbiter_contract.openDispute(hash, cb)`.
3. Inspect the outbound HTTPS request body via `httpRequest(url, "/api/dispute/new", dataJSON, ...)`: it contains `data.my_contact_info` and `data.peer_contact_info` in plaintext JSON, in addition to the properly encrypted copies inside `data.encrypted_contract`.
4. The arbstore server (which cannot decrypt `encrypted_contract`) can trivially read both parties' contact info directly from the plaintext fields, confirming the disclosure. [4](#0-3)

### Citations

**File:** arbiter_contract.js (L262-319)
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
					db.query("SELECT 1 FROM assets WHERE unit IN(?) AND is_private=1 LIMIT 1", [objContract.asset], function(rows){
						if (rows.length > 0) {
							data.asset = objContract.asset;
							data.amount = objContract.amount;
						}
						var dataJSON = JSON.stringify(data);
						httpRequest(url, "/api/dispute/new", dataJSON, function(err, resp) {
							if (err)
								return cb(err);

							setField(hash, "status", "in_dispute", function(objContract) {
								shareUpdateToPeer(hash, "status");
								// listen for arbiter response
								db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.arbiter_address]);
								cb(null, resp, objContract);
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** arbiter_contract.js (L339-344)
```javascript
				var data = JSON.stringify({
					contract_hash: hash,
					my_pairing_code: objContract.my_pairing_code,
					my_address: objContract.my_address,
					contract: {title: objContract.title, text: objContract.text, creation_date: objContract.creation_date, me_is_payer: objContract.me_is_payer, my_address: objContract.my_address, peer_address: objContract.peer_address, my_party_name: objContract.my_party_name, peer_party_name: objContract.peer_party_name, arbiter_address: objContract.arbiter_address, amount: objContract.amount, asset: objContract.asset},
				});
```
