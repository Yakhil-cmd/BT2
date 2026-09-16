### Title
Missing Authorization on Peer-Chosen Arbiter Address Leads to Exfiltration of Confidential Contract Data via Attacker-Controlled ArbStore URL - ([File: arbiter_contract.js])

### Summary
The arbiter-contract flow in `wallet.js` accepts an `arbiter_address` supplied entirely by the remote counterparty in the `arbiter_contract_offer` device message, without verifying that this address belongs to a trusted/registered arbiter. This address is later used to resolve an ArbStore URL through the hub (`hub/get_arbstore_url`) and is used as the destination for HTTP POST requests carrying confidential contract data (encrypted contract, contact info, pairing codes, amount, asset) in `openDispute()`, `appeal()`, and `getAppealFee()` in `arbiter_contract.js`. This mirrors the Elasticsearch bug class (CWE-862, Missing Authorization / CAPEC-122 Privilege Abuse): a party with limited "contract counterparty" privilege can steer sensitive outbound traffic to a destination of their choosing.

### Finding Description
When a peer sends an `arbiter_contract_offer` device message, the handler in `wallet.js` validates only that `body.arbiter_address` is a syntactically valid address: [1](#0-0) 
There is no check that `arbiter_address` corresponds to a known, vetted arbiter (e.g., cross-checked against `wallet_arbiters`, an attestation, or an allow-list). The contract, including this attacker-chosen `arbiter_address`, is stored via `arbiter_contract.store()`: [2](#0-1) 

Once the local user accepts the offer and the contract proceeds (`paid`/`in_dispute`), `openDispute()` uses this untrusted `arbiter_address` to resolve a URL from the hub and then POSTs sensitive contract data to it: [3](#0-2) 

The same pattern is repeated in `appeal()` and `getAppealFee()`, which also derive the destination URL from the counterparty-supplied `arbiter_address`/`arbstore_address` and POST/GET confidential data to it: [4](#0-3) 

`arbiters.getInfo()` and `arbiters.getArbstoreInfo()` similarly resolve a URL via `device.requestFromHub("hub/get_arbstore_url", address, ...)` and then makes outbound HTTPS requests to whatever URL is returned for that address: [5](#0-4) [6](#0-5) 

Because the `arbiter_address` used as the lookup key is fully attacker-chosen (any peer proposing a contract can name any address as the "arbiter", subject only to `isValidAddress`), an attacker who also controls (or registers as) that address's ArbStore mapping on the hub can cause the victim's wallet to direct outbound HTTP(S) traffic — carrying the `encrypted_contract` package, `my_pairing_code`, `peer_pairing_code`, contact info, dispute amount, and private-asset details — to an endpoint they control. This is the same bug class as the Elasticsearch CVE: a user/component holding only a narrow, unprivileged capability (proposing a contract / naming an "arbiter") is able to redirect privileged outbound network operations (which in the ordinary flow are meant to go only to the true, vetted ArbStore) to an arbitrary destination, exposing what should be confidential negotiation data (pairing secrets/pairing codes that could be used to impersonate or re-pair, contract terms, and financial details).

### Impact Explanation
An attacker acting merely as a contract counterparty (a peer the victim has paired with or is willing to negotiate a contract with) can:
- Force the victim's wallet to send `my_pairing_code`/`peer_pairing_code`, encrypted contract text, and dispute financial details (amount, asset, private-payment info for private assets) to a server the attacker controls, by proposing a contract with a self-chosen `arbiter_address` whose ArbStore mapping the attacker also controls.
- Harvest pairing codes that can facilitate further device impersonation/social-engineering, and obtain confidential negotiation/contract content that was intended to remain between the two parties and the legitimate arbiter only.

This qualifies as information disclosure of "administrator/user-provisioned credentials" analog (pairing secrets/pairing codes function similarly to credentials used to authenticate/re-establish a paired relationship) and constitutes unauthorized data exfiltration reachable purely from a device message sent by an unprivileged paired counterparty — matching the required "concrete" impact bar (loss of confidentiality of private-payment/negotiation data and pairing secrets that could be leveraged for further account takeover of the messaging channel).

### Likelihood Explanation
Likelihood is high for a determined counterparty: no privileged access is required beyond being paired/correspondent with the victim and offering an arbiter contract, which is a normal, exposed user-facing wallet feature. The victim need only accept normal application flow (accept the offer, and proceed to `paid`/`in_dispute`/`appeal`), at which point the outbound request is sent automatically by the wallet code, with no additional confirmation that the `arbiter_address`/resolved URL is trustworthy.

### Recommendation
- Before using `arbiter_address` to resolve an ArbStore URL and send confidential data, cross-check the address against a locally curated/attested allow-list of known arbiters (e.g., verify via `wallet_arbiters`, attestor-signed data feed, or another authenticated registry) rather than accepting any peer-supplied, syntactically valid address.
- When displaying the contract offer to the user in `arbiter_contract_offer` handling, surface the arbiter's identity/verification status so the user can decline offers with unknown/unverified arbiters.
- Consider pinning/validating that the ArbStore URL returned by the hub for a given `arbiter_address` matches an expected, previously verified value (e.g., certificate pinning or a signed mapping) before sending `encrypted_contract`, pairing codes, or financial details over HTTP(S) in `openDispute`, `appeal`, and `getAppealFee`.
- Redact or minimize the pairing codes/contact info sent in the dispute/appeal payloads, or otherwise avoid propagating reusable secrets to third-party URLs resolved from unauthenticated input.

### Proof of Concept
1. Attacker pairs with victim's wallet as a normal correspondent device.
2. Attacker sends `arbiter_contract_offer` with `arbiter_address` = an address the attacker controls (this only needs to pass `ValidationUtils.isValidAddress`), per the handler at `wallet.js:617-654`.
3. Attacker ensures the hub's `hub/get_arbstore_url` for that `arbiter_address` resolves to a URL under attacker control (or otherwise controls the ArbStore mapping for the chosen address).
4. Victim accepts the offer through normal UI flow; contract proceeds to `paid`, and later victim (or attacker) triggers a dispute (`arbiter_contract.openDispute`) or appeal (`arbiter_contract.appeal`/`getAppealFee`).
5. Victim's wallet automatically calls `httpRequest(url, "/api/dispute/new", dataJSON, ...)` (`arbiter_contract.js:303`) sending `encrypted_contract`, `my_pairing_code`, `peer_pairing_code`, contact info, and (for private assets) `amount`/`asset`, directly to the attacker-controlled URL.

Note: I was unable to fully inspect `fillArbstoreAddresses()` and the hub-side `hub/get_arbstore_url` handler implementation in `network.js` within the available search iterations, so I cannot confirm with certainty whether the hub enforces any additional authorization on the `arbiter_address → arbstore URL` mapping (e.g., requiring the arbiter to have proven ownership via a signed record) that might partially mitigate this. If such server-side validation exists and is robust, the practical exploitability would be reduced to scenarios where the attacker can register/control the ArbStore mapping for an address they name as "arbiter." This should be verified by reviewing `network.js`'s `hub/get_arbstore_url` handler and `arbiter_contract.js`'s `fillArbstoreAddresses` function directly.

### Citations

**File:** wallet.js (L617-627)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
```

**File:** wallet.js (L647-654)
```javascript
				db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.my_address], function(rows) {
					if (!rows.length)
						return callbacks.ifError("contract does not contain my address");
					arbiter_contract.store(body, false, function() {
						eventBus.emit("arbiter_contract_offer", body.hash);
						callbacks.ifOk();
					});
				});
```

**File:** arbiter_contract.js (L262-303)
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
```

**File:** arbiter_contract.js (L321-375)
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
	});
}

function getAppealFee(hash, cb) {
	getByHash(hash, function(objContract){
		var command = "hub/get_arbstore_url";
		var address = objContract.arbiter_address;
		if (objContract.arbstore_address) {
			command = "hub/get_arbstore_url_by_address";
			address = objContract.arbstore_address;
		}
		device.requestFromHub(command, address, function(err, url){
			if (err)
				return cb("can't get arbstore url:", err);
			httpRequest(url, "/api/get_appeal_fee", "", function(err, resp) {
				if (err)
					return cb(err);
				cb(null, resp);
			});
		});
	});
}
```

**File:** arbiters.js (L10-49)
```javascript
function getInfo(address, cb) {
	cb = cb || function() {};
	db.query("SELECT device_pub_key, real_name FROM wallet_arbiters WHERE arbiter_address=?", [address], function(rows){
		if (rows.length && rows[0].real_name) { // request again if no real name
			cb(null, rows[0]);
		} else {
			device.requestFromHub("hub/get_arbstore_url", address, function(err, url){
				if (err) {
					return cb(err);
				}
				if (!validationUtils.isNonemptyString(url))
					return cb("invalid url received from hub");
				requestInfoFromArbStore(url+'/api/arbiter/'+address, function(err, info){
					if (err) {
						return cb(err);
					}
					if (!validationUtils.isNonemptyObject(info))
						return cb("invalid arbiter info received from arbstore");
					db.query("REPLACE INTO wallet_arbiters (arbiter_address, device_pub_key, real_name) VALUES (?, ?, ?)", [address, info.device_pub_key, info.real_name], function() {cb(null, info);});
				});
			});
		}
	});
}

function requestInfoFromArbStore(url, cb){
	http.get(url, function(resp){
		var data = '';
		resp.on('data', function(chunk){
			data += chunk;
		});
		resp.on('end', function(){
			try {
				cb(null, JSON.parse(data));
			} catch(ex) {
				cb(ex);
			}
		});
	}).on("error", cb);
}
```

**File:** arbiters.js (L51-80)
```javascript
function getArbstoreInfo(arbiter_address, cb) {
	if (!cb)
		return new Promise(function(resolve, reject){
			getArbstoreInfo(arbiter_address, function(err, info){
				if (err) return reject(err);
				resolve(info);
			});
		});
	if (arbStoreInfos[arbiter_address]) return cb(null, arbStoreInfos[arbiter_address]);
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err) {
			return cb(err);
		}
		if (!validationUtils.isNonemptyString(url))
			return cb("invalid url received from hub");
		requestInfoFromArbStore(url+'/api/get_info', function(err, info){
			if (err)
				return cb(err);
			if (!validationUtils.isNonemptyObject(info))
				return cb("invalid info received from arbstore");
			const cut = parseFloat(info.cut);
			if (!info.address || !validationUtils.isValidAddress(info.address) || isNaN(cut) || cut < 0 || cut >= 1) {
				return cb("malformed info received from ArbStore");
			}
			info.url = url;
			arbStoreInfos[arbiter_address] = info;
			cb(null, info);
		});
	});
}
```
