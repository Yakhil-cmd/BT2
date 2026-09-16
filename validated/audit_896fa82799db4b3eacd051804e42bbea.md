[1](#0-0) 

### Title
SSRF via unvalidated arbstore URL in arbiter contract HTTP requests - (File: arbiter_contract.js)

### Summary
The wallet's arbiter-contract feature performs outbound HTTPS requests to a URL that is ultimately controlled by whichever entity a peer names as the "arbiter" of a private contract. `httpRequest()` builds request options directly from `url.parse(host)` with no validation of scheme, host, or port before dispatching the request, mirroring the CVE-2019-10686 pattern where a user-influenced URL/host string is passed unchecked into an outbound HTTP call (SSRF).

### Finding Description
When a device pairs and proposes an arbiter contract via `device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_offer", objContractForPeer)`, the offer includes an `arbiter_address` chosen entirely by the offering peer (an untrusted counterparty in the private-payment flow), stored via `store()` at [2](#0-1) .

Later wallet operations — `openDispute`, `appeal`, `getAppealFee`, and `getArbstoreAddresses` — resolve this attacker-influenced `arbiter_address` to a URL via `device.requestFromHub("hub/get_arbstore_url", ...)` and then call `httpRequest(url, path, data, cb)`: [3](#0-2) [4](#0-3) 

`httpRequest` builds the request purely from the returned `url` string with no allow-list or scheme/host restriction: [1](#0-0) 

The only check anywhere on this path is `validationUtils.isNonemptyString(url)` in `arbiters.js`, which does not restrict the value to a safe HTTP(S) endpoint, host, or port: [5](#0-4) [6](#0-5) 

Because the arbiter identity (and therefore the resolved URL) is a value that any peer proposing a private contract can pick, and the wallet automatically issues POST requests carrying sensitive data — pairing codes, contract text, encrypted contract payloads, and payment amounts — to that resolved endpoint (`openDispute`, `appeal`), an attacker acting as arbiter/counterparty can steer these requests to arbitrary hosts (e.g., internal/loopback addresses or metadata services reachable from the user's machine), analogous to the mishandled-URL SSRF class in the CVE report.

### Impact Explanation
A malicious counterparty who gets a victim to accept an arbiter contract naming an attacker-registered arbiter can cause the victim's wallet to send POST requests — including pairing secrets, contact info, and encrypted contract details — to attacker-chosen hosts/ports (`/api/dispute/new`, `/api/appeal/new`, `/api/get_appeal_fee`, `/api/get_device_address`). This is a data-exfiltration and internal-network-probing (SSRF) primitive from an unprivileged private-payment counterparty, without requiring any hub or node compromise.

### Likelihood Explanation
Reachable purely by a paired device/private-payment counterparty proposing an arbiter contract with a self-controlled arbiter address (registering an arbstore URL through the normal arbiter/arbstore flow) and getting the victim to proceed to dispute/appeal/fee-lookup actions — all standard, unprivileged wallet operations. No special network position or node privileges are required.

### Recommendation
Validate the arbstore URL before making requests: enforce `https://` scheme, disallow private/loopback/link-local IP ranges and non-standard ports, and consider pinning known arbstore hosts or requiring hub-side certification of arbstore URLs. Apply the same validation uniformly in `arbiter_contract.js`'s `httpRequest` and `arbiters.js`'s `requestInfoFromArbStore`/`getArbstoreInfo`.

### Proof of Concept
1. Attacker device registers as an "arbiter" whose `hub/get_arbstore_url` resolves to an attacker-controlled or internal-network URL (e.g., `http://127.0.0.1:PORT` or an internal service address).
2. Attacker sends `arbiter_contract_offer` to victim naming themselves (or a colluding address) as `arbiter_address`, per `createAndSend()` at [7](#0-6) .
3. Victim accepts and later calls `openDispute`/`appeal`/`getAppealFee` on the contract.
4. Victim's node resolves the arbiter address to the attacker's URL and issues an HTTPS POST containing pairing codes and encrypted contract data to that host, per [8](#0-7) , demonstrating SSRF/data exfiltration to an attacker-chosen endpoint.

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

**File:** arbiter_contract.js (L91-97)
```javascript
function store(objContract, bFromCosigner, cb) { // contracts shared by cosigners are trusted to reflect their true status
	const me_is_cosigner = bFromCosigner ? 1 : 0;
	const status = bFromCosigner ? (objContract.status || status_PENDING) : status_PENDING;
	var fields = "(hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, peer_pairing_code, peer_contact_info, my_pairing_code, my_contact_info, me_is_cosigner";
	var placeholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 1, objContract.creation_date, objContract.ttl, status, objContract.title, objContract.text, objContract.peer_pairing_code, objContract.peer_contact_info, objContract.my_pairing_code, objContract.my_contact_info, me_is_cosigner];
	if (bFromCosigner) {
```

**File:** arbiter_contract.js (L228-245)
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
```

**File:** arbiter_contract.js (L262-318)
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
```

**File:** arbiter_contract.js (L357-375)
```javascript
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

**File:** arbiter_contract.js (L377-409)
```javascript
function httpRequest(host, path, data, cb) {
	var reqParams = Object.assign(url.parse(host),
		{
			path: path,
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Content-Length": (new TextEncoder().encode(data)).length
			}
		}
	);
	var req = http.request(
		reqParams,
		function(resp){
			var data = "";
			resp.on("data", function(chunk){
				data += chunk;
			});
			resp.on("end", function(){
				try {
					data = JSON.parse(data);
					if (data.error) {
						return cb(data.error);
					}
					cb(null, data);
				} catch (e) {
					cb(e);
				}
			});
		}).on("error", cb);
	req.write(data);
	req.end();
}
```

**File:** arbiters.js (L16-33)
```javascript
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

**File:** arbiters.js (L35-49)
```javascript
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
