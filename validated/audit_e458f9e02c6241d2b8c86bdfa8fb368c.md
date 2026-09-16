### Title
SSRF via attacker-controlled arbstore/arbiter URL fetched by raw `http.request` in arbiter contract flow - (File: arbiter_contract.js)

### Summary
The Firecrawl SSRF (CVE-2024-56800) is a case of the scraping engine fetching a remotely-supplied URL without validating that it does not resolve to an internal/link-local address. `ocore`'s arbiter-contract subsystem has the same bug-class: it resolves an `arbiter_address`/`arbstore_address` supplied by the contract counterparty to a URL and then issues a raw outbound HTTP request to that URL with no restriction on the destination host.

### Finding Description
`arbiter_contract.js` exposes a peer-to-peer "arbiter contract" negotiation flow. A contract offer/response/shared message received from a paired device (the private-payment counterparty) is persisted via `store()`, which writes attacker-supplied contract fields, including the arbiter/arbstore identity, into `wallet_arbiter_contracts` [1](#0-0) . `device.sendMessageToDevice(..., "arbiter_contract_offer"/"arbiter_contract_response"/"arbiter_contract_shared", ...)` is how a counterparty pushes this data into the local wallet without any validation of the arbstore identity beyond its format [2](#0-1) .

When the local user later interacts with the contract (e.g., appealing a dispute or checking the appeal fee), the code resolves the arbiter/arbstore address to a URL via the hub and then makes an unrestricted outbound HTTP POST to that URL using Node's low-level `http.request`: [3](#0-2) 

The `httpRequest()` helper builds request parameters directly from `url.parse(host)` and calls `http.request()` with no allow-list/deny-list for private, loopback, or link-local IP ranges (e.g., `127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`) [4](#0-3) . The same unrestricted pattern also appears in `arbiters.js` (`requestInfoFromArbStore`) for fetching arbiter/arbstore info [5](#0-4) , and again in `uri.js`'s `fetchUrl()` used when parsing a `data?app=definition` link whose `definition` value starts with `https://` [6](#0-5) [7](#0-6) .

Because the arbiter/arbstore identity that seeds the eventual URL originates from the private-payment counterparty's contract proposal, an attacker who runs their own arbstore/arbiter service and registers it with the hub can steer the victim wallet's `httpRequest()` at an internal address (loopback, cloud metadata endpoint, LAN service) once the victim triggers an appeal or fee lookup on the malicious contract.

### Impact Explanation
A successful SSRF lets a malicious arbiter/arbstore counterparty force the victim's node/wallet process to make outbound HTTP requests to internal-only endpoints reachable from that process (e.g., cloud instance metadata services, local admin APIs, other services bound to `localhost`). Response bodies are parsed as JSON and may leak internal secrets/tokens back into wallet state or error messages, and the requests are made with the wallet's ambient network position — this maps to unauthorized data exfiltration / potential funds or credential compromise typically classified High for SSRF in this bug class.

### Likelihood Explanation
The victim must engage in an arbiter-contract negotiation with a malicious counterparty and later trigger `appeal()` or `getAppealFee()` on that contract — actions a normal counterparty in a dispute would plausibly perform, so likelihood is moderate rather than trivial (some social-engineering/contract-acceptance step is required, but no special privileges are needed by the attacker).

### Recommendation
Validate any resolved arbstore/arbiter URL before use in `httpRequest()`/`requestInfoFromArbStore()`/`fetchUrl()`: resolve the hostname and reject requests to private, loopback, link-local, and multicast IP ranges (RFC 1918, 127.0.0.0/8, 169.254.0.0/16, etc.), enforce `https:` scheme, and consider routing these requests through a hardened proxy that blocks internal destinations, consistent with the upstream Firecrawl fix.

### Proof of Concept
1. Attacker registers an arbstore service with the hub whose advertised URL points to an internal/loopback address (e.g., `http://127.0.0.1:PORT` or a cloud metadata IP).
2. Attacker proposes an arbiter contract to the victim referencing their own `arbiter_address`/`arbstore_address`, sent via `device.sendMessageToDevice(..., "arbiter_contract_offer", ...)` [2](#0-1) .
3. Victim's wallet stores the contract via `store()` without validating the arbstore identity [1](#0-0) .
4. Victim later calls `appeal()` or `getAppealFee()`; the wallet resolves the address to the attacker's URL via the hub and issues `httpRequest(url, "/api/appeal/new", data, cb)`, which performs a raw `http.request()` to the attacker-controlled internal target [8](#0-7) .
5. The victim's node/wallet unwittingly relays internal network responses back through the JSON parsing path, confirming SSRF.

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

**File:** arbiter_contract.js (L321-409)
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

**File:** uri.js (L124-136)
```javascript
		if (app === 'definition') {
			var definition = assocParams.definition;
			if (!definition)
				return callbacks.ifError("no definition");
			if (definition.substr(0, 8) === 'https://') {
				return fetchUrl(definition, function (err, response) {
					if (err)
						return callbacks.ifError(err);
					assocParams.definition = response;
					callbacks.ifOk(objRequest);
				});
			}
		}
```

**File:** uri.js (L251-291)
```javascript
function fetchUrl(url, cb) {
	var https = require('https');
	var bDone = false;
	function returnError(err) {
		console.log(err);
		if (bDone)
			return;
		bDone = true;
		cb(err);
	}
	try {
		https.get(url, function (resp) {
			if (resp.statusCode !== 200)
				return returnError("non-200 response while trying to fetch " + url);
			var data = '';

			// A chunk of data has been recieved.
			resp.on('data', function(chunk) {
				data += chunk;
			});

			// aborted before the whole response has been received
			resp.on('aborted', function () {
				returnError("connection aborted while trying to fetch " + url);
			});

			// The whole response has been received
			resp.on('end', function () {
				if (bDone)
					return;
				bDone = true;
				cb(null, data);
			});
		}).on("error", function(err) {
			returnError("non-200 response while trying to fetch " + url + ": " + err.message);
		});
	}
	catch(err) {
		returnError(err.message);
	}
}
```
