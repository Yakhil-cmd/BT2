### Title
Arbiter contract dispute/appeal flow leaks private contact info and pairing secrets to an attacker-chosen "arbiter" endpoint - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` lets a peer counterparty propose an `arbiter_address` as part of an arbiter contract offer (`createAndSend` / `store`, no validation that `arbiter_address` is a real, trusted arbiter). When the local user later calls `openDispute()`, `appeal()`, or `getAppealFee()`, the wallet resolves this attacker-supplied `arbiter_address` via `device.requestFromHub("hub/get_arbstore_url", ...)` and then POSTs a JSON payload directly to the returned URL with `httpRequest()`. That payload contains sensitive material that should stay within the sphere of the actual contract counterparties/arbiter: the user's and peer's `my_pairing_code` / `peer_pairing_code` (device pairing secret + hub + pubkey, i.e. credentials that let a new device pair to that wallet's contacts), `my_contact_info`/`peer_contact_info`, and for private assets the `asset` and `amount`.

### Finding Description
`openDispute` builds a `data` object including `my_pairing_code`, `peer_pairing_code`, `my_contact_info`, `peer_contact_info`, and (for private assets) `asset`/`amount`, then sends it via `httpRequest(url, "/api/dispute/new", ...)` [1](#0-0) . `appeal` does the same, sending `my_pairing_code`, contract title/text, party names, addresses, amount and asset to `/api/appeal/new` [2](#0-1) . The destination `url` is obtained purely from `arbiter_address`, a field that originates from the contract itself (set by whichever party created/offered the contract via `createAndSend`) and is stored via `store()` without verifying that this address is a legitimate, previously-known arbiter [3](#0-2) [4](#0-3) . `getArbstoreAddresses`/`fillArbstoreAddresses` similarly resolve `arbstore_device_address` from an HTTP call to the hub-provided URL for this address, with no restriction that the URL must belong to a known/verified ArbStore [5](#0-4) .

This is directly analogous to the Ironic bug class (CWE-669, incorrect resource transfer between spheres): a resource that should be confined to the "trusted arbiter/import target" sphere is transferred to an endpoint effectively controllable by the counterparty who supplied `arbiter_address` in the contract they offered — sending along authorization-equivalent data (`pairing_code`, which is a live pairing secret / device credential) and private contact/financial info.

### Impact Explanation
If a malicious counterparty proposes an arbiter contract using an `arbiter_address` they control (or one whose registered ArbStore URL resolves to an attacker-controlled host, e.g. by having the hub's `hub/get_arbstore_url` mapping seeded to attacker infrastructure), then when the victim raises a dispute or appeal, the victim's device sends its pairing secret (`my_pairing_code`) and the peer's pairing secret, private contact info, and — for private assets — the exact asset and amount, straight to that attacker-controlled endpoint. A leaked pairing code allows an attacker to pair a new device as a trusted correspondent of the victim's wallet, which can be leveraged for follow-on social engineering, further private-data disclosure (private payment chains are shared with correspondents), or facilitate future fraud. This satisfies "AA fund loss/freezing"-adjacent and "unauthorized" resource exposure impact criteria at High severity given CWE-669's cross-sphere data exfiltration nature.

### Likelihood Explanation
Likelihood is high for an attacker who is simply a counterparty to an arbiter contract: they fully control the `arbiter_address` value proposed in the contract offer (`createAndSend`), and standard flows (`openDispute`, `appeal`) are triggered by ordinary user action (e.g., disputing a payment) without any independent verification that the resolved ArbStore URL is legitimate before pairing-code data is transmitted.

### Recommendation
- Before sending any dispute/appeal payload, verify that `arbiter_address` corresponds to a well-known/whitelisted arbiter (e.g., cross-check against a trusted registry or require out-of-band confirmation), not just whatever the offering peer supplied.
- Do not include `my_pairing_code`/`peer_pairing_code` in the payload sent to the ArbStore unless it's cryptographically bound/necessary and the ArbStore's device pubkey has been authenticated (the code already encrypts `encrypted_contract` to `objArbiter.device_pub_key` in `openDispute` — pairing codes and contact info should be similarly protected or omitted from the plaintext JSON POST).
- Validate/authenticate the ArbStore URL returned by the hub (e.g., pinned/allow-listed hosts, TLS certificate checks) before making outbound `httpRequest` calls with sensitive data.

### Proof of Concept
1. Attacker (peer) offers an arbiter contract to the victim via `createAndSend`, setting `arbiter_address` to an address the attacker controls (or whose associated hub `hub/get_arbstore_url` record points to an attacker-run HTTP server).
2. Victim accepts and pays; a dispute later arises and the victim calls `openDispute(hash, cb)`.
3. `openDispute` resolves the URL for `objContract.arbiter_address` via the hub and POSTs to `<attacker_url>/api/dispute/new` a JSON body including `my_pairing_code`, `peer_pairing_code`, `my_contact_info`, `peer_contact_info`, and (if the asset is private) `asset`/`amount` [6](#0-5) .
4. The attacker's server receives the victim's live pairing secret and private contract details, which it can use to pair a rogue device as a correspondent of the victim's wallet or otherwise misuse the leaked private information.

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

**File:** arbiter_contract.js (L91-116)
```javascript
function store(objContract, bFromCosigner, cb) { // contracts shared by cosigners are trusted to reflect their true status
	const me_is_cosigner = bFromCosigner ? 1 : 0;
	const status = bFromCosigner ? (objContract.status || status_PENDING) : status_PENDING;
	var fields = "(hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, peer_pairing_code, peer_contact_info, my_pairing_code, my_contact_info, me_is_cosigner";
	var placeholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 1, objContract.creation_date, objContract.ttl, status, objContract.title, objContract.text, objContract.peer_pairing_code, objContract.peer_contact_info, objContract.my_pairing_code, objContract.my_contact_info, me_is_cosigner];
	if (bFromCosigner) {
		if (objContract.shared_address) {
			fields += ", shared_address";
			placeholders += ", ?";
			values.push(objContract.shared_address);
		}
		if (objContract.unit) {
			fields += ", unit";
			placeholders += ", ?";
			values.push(objContract.unit);
		}
	}
	fields += ")";
	placeholders += ")";
	db.query("INSERT "+db.getIgnore()+" INTO wallet_arbiter_contracts "+fields+" VALUES "+placeholders, values, function(res) {
		if (cb) {
			cb(res);
		}
	});
}
```

**File:** arbiter_contract.js (L228-260)
```javascript
function getArbstoreAddresses(arbiter_address, cb) {
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err)
			return cb(err);
		device.requestFromHub("hub/get_arbstore_address", arbiter_address, function(err, arbstore_address){
			if (err) {
				return cb(err);
			}
			httpRequest(url, "/api/get_device_address", "", function(err, arbstore_device_address) {
				if (err) {
					console.warn("no arbstore_device_address", err);
					return cb(err);
				}
				cb(null, { arbstore_address, arbstore_device_address });
			});
		});
	});
}

function fillArbstoreAddresses(objContract, cb) {
	if (!cb)
		return new Promise(resolve => fillArbstoreAddresses(objContract, resolve));
	if (objContract.arbstore_device_address && objContract.arbstore_address)
		return cb();
	getArbstoreAddresses(objContract.arbiter_address, function(err, result) {
		if (err)
			return cb(err);
		var { arbstore_address, arbstore_device_address } = result;
		objContract.arbstore_address = arbstore_address;
		objContract.arbstore_device_address = arbstore_device_address;
		db.query("UPDATE wallet_arbiter_contracts SET arbstore_address=?, arbstore_device_address=? WHERE hash=?", [arbstore_address, arbstore_device_address, objContract.hash], function () { cb(); });
	});
}
```

**File:** arbiter_contract.js (L262-317)
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
```

**File:** arbiter_contract.js (L321-355)
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
```
