### Title
SSRF via unvalidated ArbStore URL fetch in arbiter contract flow - ([File: arbiters.js])

### Summary
`arbiters.js` and `arbiter_contract.js` fetch a URL that is resolved from an `arbiter_address` supplied by an untrusted private-payment counterparty, and then issue raw HTTP/HTTPS GET/POST requests to that URL with no validation that it does not point to a loopback, link-local, or private/internal IP range — mirroring the LMDeploy `load_image()` SSRF pattern (unvalidated URL fetch reachable from attacker-controlled input).

### Finding Description
When a peer sends an `arbiter_contract_offer` device message, the receiving wallet stores the peer-supplied `arbiter_address` directly via `store()` without validating that it belongs to any known/trusted arbiter registry: [1](#0-0) 

Later, when the victim wallet needs arbiter information (e.g. `getInfo`, `getArbstoreInfo`, `openDispute`, `appeal`, `getAppealFee`), it resolves a URL for that `arbiter_address` via `device.requestFromHub("hub/get_arbstore_url", address, ...)`. Because the attacker fully controls the `arbiter_address` they proposed (it is their own address, tied to their own home hub), the attacker's hub can return an arbitrary URL string (e.g. `http://169.254.169.254/latest/meta-data/...` or `http://127.0.0.1:PORT/...`) in response: [2](#0-1) 

That URL is then fetched with no validation of scheme, hostname, or IP address: [3](#0-2) 

The same unvalidated pattern is repeated in `getArbstoreAddresses`, `openDispute`, `appeal`, and `getAppealFee` in `arbiter_contract.js`, all of which call `httpRequest(url, path, data, cb)`, which performs `http.request` directly against the attacker-influenced `url` with no allow/deny-list checks: [4](#0-3) [5](#0-4) [6](#0-5) 

There is no `is_safe_url`-style check anywhere in these files (no blocklist for `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`), exactly matching the missing validation described in the LMDeploy advisory.

### Impact Explanation
An unprivileged private-payment counterparty who proposes an arbiter contract (a normal, unprivileged wallet-to-wallet interaction) can steer the victim's wallet process into issuing outbound HTTP/HTTPS requests (including POST requests carrying dispute/appeal data such as `my_pairing_code`, contact info, and encrypted contract details) to attacker-chosen internal targets. This can be used to reach cloud metadata endpoints, internal-only services, or loopback-bound admin interfaces reachable from the host running the wallet/hub process, and additionally leaks wallet dispute data (pairing codes, contact info) to whatever endpoint the attacker's hub directs the request to. This is a legitimate SSRF impact within the wallet/contract-message handling surface named in scope.

### Likelihood Explanation
Likelihood is high: the only requirement is that the attacker runs their own hub for the `arbiter_address` they propose in an `arbiter_contract_offer` (a normal, permissionless action any wallet user can take), and that the victim engages with the arbiter-contract flow (accepts/opens dispute/appeals or simply calls `arbiters.getInfo`). No compromise of the real network hub or any privileged component is required.

### Recommendation
Before performing any outbound HTTP(S) request to a URL obtained via `hub/get_arbstore_url` / `hub/get_arbstore_url_by_address`, validate the URL: enforce `https` scheme, resolve the hostname, and reject requests whose resolved IP falls into loopback, link-local, or private ranges (mirroring the `is_safe_url` fix pattern from the referenced advisory). Apply this validation centrally in `requestInfoFromArbStore` (`arbiters.js`) and `httpRequest` (`arbiter_contract.js`) so all ArbStore-URL consumers are covered.

### Proof of Concept
1. Attacker wallet A sends `arbiter_contract_offer` to victim wallet B with `arbiter_address` = an address A controls, whose home hub is run by A.
2. Victim B accepts/opens a dispute; B's wallet calls `arbiters.getInfo(arbiter_address, cb)` → `device.requestFromHub("hub/get_arbstore_url", arbiter_address, ...)`.
3. A's hub responds to the `hub/get_arbstore_url` request with `url = "http://169.254.169.254"` (or `http://127.0.0.1:22`).
4. `requestInfoFromArbStore(url + '/api/arbiter/' + address, cb)` in `arbiters.js:22,35-49` performs `http.get(url,...)` directly against the attacker-chosen internal address, with the response parsed and returned to B's wallet — demonstrating unauthenticated, unvalidated SSRF from a private-payment counterparty message.

### Citations

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
