### Title
Server-Side Request Forgery via unvalidated arbstore URL in arbiter contract flow - (File: `arbiters.js`, `arbiter_contract.js`)

### Summary
When a wallet participates in an arbiter-mediated contract, it resolves the arbiter's ArbStore URL through the hub (`device.requestFromHub("hub/get_arbstore_url", arbiter_address)`), validates only that the returned value is a non-empty string, and then issues unauthenticated HTTP `GET`/`POST` requests to that URL. Since the arbiter address (and therefore the ArbStore URL registered for it) is fully controlled by whichever party the user selects/accepts as an arbiter, a malicious "arbiter" can point the URL at an internal or otherwise restricted host, causing the victim node to make arbitrary outbound requests — a classic SSRF (CWE-918), directly analogous to the reported MobSF `allow_redirects=True` issue where a server blindly follows/sends requests to attacker-supplied URLs.

### Finding Description
`arbiters.js` resolves the ArbStore URL for an `arbiter_address` from the hub and only checks `validationUtils.isNonemptyString(url)` before using it: [1](#0-0) 
The URL is then dereferenced directly with `http.get(url, ...)` in `requestInfoFromArbStore`, with no restriction on scheme, host, or destination IP range: [2](#0-1) 

The same unvalidated-URL pattern repeats in `arbiter_contract.js`, where `getArbstoreAddresses`/`fillArbstoreAddresses`/`appeal`/`getAppealFee` all fetch the URL via `hub/get_arbstore_url`/`hub/get_arbstore_url_by_address` and then call `httpRequest(url, path, data, cb)`, which builds a raw HTTP request from `url.parse(host)` with no allow-list or private-network filtering: [3](#0-2) [4](#0-3) [5](#0-4) 

The `arbiter_address` used to key these lookups originates from the contract object exchanged directly between wallets over `arbiter_contract_offer` device messages, chosen by whichever peer proposes the contract: [6](#0-5) [7](#0-6) 

Any user can register an address as an "arbiter" and have its ArbStore URL stored on the hub; there is no verification tying the address to a trustworthy/real arbitration service, and no sanitization of the retrieved URL (e.g., rejecting `http://`, loopback/link-local/private IP ranges, non-standard ports, or requiring an allow-listed set of known ArbStore hosts).

### Impact Explanation
A malicious counterparty who gets a victim to accept an arbiter contract naming an attacker-controlled `arbiter_address` (or an attacker who simply registers as an "arbiter" that others discover/select) can force the victim's node to issue outbound `GET`/`POST` requests to arbitrary hosts, including internal-only network services (e.g., cloud metadata endpoints, internal admin/RPC interfaces reachable from the machine running the wallet/hub). The `POST` requests in `appeal`/`get_appeal_fee` also carry attacker-influenced JSON bodies (contract hash, addresses, amounts) to the SSRF target, which can be leveraged against internal services expecting structured input. This can lead to information disclosure of internal services or triggering unintended actions on internal infrastructure, consistent with the CVSS High rating of the referenced advisory (Confidentiality impact, network-reachable, no privileges/UI needed beyond normal contract participation).

### Likelihood Explanation
Likelihood is high in practice: setting up an arbiter contract with a self-chosen or peer-suggested arbiter is a normal, unprivileged user workflow (`createAndSend`/`store` in `arbiter_contract.js`), and no server-side or client-side validation restricts the arbstore URL's scheme or target IP range before the wallet's own network stack fetches it.

### Recommendation
- Validate the ArbStore URL returned from the hub: enforce `https://` scheme, and resolve/reject requests targeting private, loopback, link-local, or multicast IP ranges (RFC1918, 127.0.0.0/8, 169.254.0.0/16, etc.) before connecting.
- Consider maintaining a signed/allow-listed registry of legitimate ArbStore endpoints rather than trusting an arbitrary hub-provided string per arbiter address.
- Apply the same validation to both `arbiters.js` (`requestInfoFromArbStore`) and `arbiter_contract.js` (`httpRequest`), including for the `getArbstoreAddresses`/`appeal`/`getAppealFee` call sites.

### Proof of Concept
1. Attacker generates an address `A` and registers it with a hub as an arbiter, setting its ArbStore URL (via `hub/get_arbstore_url`) to `http://169.254.169.254/latest/meta-data/` or an internal service address, e.g. `http://127.0.0.1:6875/api/admin`.
2. Attacker proposes (or convinces) a victim to create/accept an arbiter contract with `arbiter_address = A` via `createAndSend`/`store` in `arbiter_contract.js`.
3. When the victim's wallet calls `arbiters.getInfo(A, cb)` or `arbiter_contract.fillArbstoreAddresses`/`appeal`, it retrieves the attacker-controlled URL from the hub and issues `http.get`/`httpRequest` directly to it — reaching internal infrastructure reachable only from the victim's node, with no scheme/IP validation performed.

### Citations

**File:** arbiters.js (L16-22)
```javascript
			device.requestFromHub("hub/get_arbstore_url", address, function(err, url){
				if (err) {
					return cb(err);
				}
				if (!validationUtils.isNonemptyString(url))
					return cb("invalid url received from hub");
				requestInfoFromArbStore(url+'/api/arbiter/'+address, function(err, info){
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

**File:** arbiter_contract.js (L321-354)
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
