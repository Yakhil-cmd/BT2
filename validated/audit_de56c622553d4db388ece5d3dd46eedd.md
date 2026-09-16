### Title
Blind SSRF via unvalidated arbiter/ArbStore URL fetched from hub for attacker-supplied `arbiter_address` - (File: arbiters.js, arbiter_contract.js)

### Summary
`arbiters.js` and `arbiter_contract.js` resolve a URL for an `arbiter_address` by querying the pairing hub (`device.requestFromHub("hub/get_arbstore_url", address, ...)`), and then immediately issue a server-side HTTP(S) request to that URL with zero validation of scheme, host, or destination (no allow-list, no check for private/loopback/link-local addresses). This mirrors the MagicMirror `CHECK_ARTICLE_URL` pattern: an attacker-influenced identifier (there: an article URL; here: an `arbiter_address`/hub response) drives an unauthenticated, unvalidated server-side fetch.

### Finding Description
`arbiters.js` `requestInfoFromArbStore()` does a raw `http.get(url, ...)` [1](#0-0)  where `url` is whatever the hub returns for `hub/get_arbstore_url` [2](#0-1) . The same unvalidated pattern is used for the arbiter cut/info lookup [3](#0-2) .

`arbiter_contract.js` reuses the identical flow for appeals and appeal-fee retrieval, building an `http.request()` to a host taken straight from the hub response and posting attacker/local-supplied JSON to an arbitrary path with no host/scheme validation: [4](#0-3) [5](#0-4) , and also for `getArbstoreAddresses()` [6](#0-5) .

The entry point that supplies the attacker-controlled `arbiter_address` is a device message from a paired counterparty: `store()` inserts a contract offer including an arbitrary `arbiter_address` field received from the peer device without any restriction on which address can be named as arbiter [7](#0-6) , and `createAndSend()`/the contract flow subsequently drives calls into `arbiters.getInfo`/`getArbstoreInfo` and `arbiter_contract.appeal`/`getAppealFee`/`getArbstoreAddresses`, all of which trust whatever URL the hub for that `arbiter_address` returns and fetch it blindly.

Because the hub that "owns" an address is chosen by whoever controls that address (any wallet/AA counterparty can name any hub in their pairing string, and a self-hosted or malicious hub can simply answer `hub/get_arbstore_url` with any string, e.g. `http://127.0.0.1:6379/`, `http://169.254.169.254/latest/meta-data/`, or an internal service URL), a paired device counterparty (or a private-payment/contract counterparty proposing an arbiter contract) can force the victim's ocore node to perform an outbound HTTP(S) request to an arbitrary internal or external host, chosen entirely by the attacker.

### Impact Explanation
This is a genuine blind SSRF primitive reachable from a paired-device / private-payment counterparty without any special privilege: the victim node performs server-side HTTP requests (GET/POST with JSON body) to attacker-chosen hosts/ports. This enables internal network/port reconnaissance, interaction with internal-only services (metadata endpoints, internal admin APIs, local databases), and can be used as a trigger/side-effect primitive against anything reachable from the node's network namespace. It does not directly cause double-spend or fund loss, but it is a concrete network-reachable SSRF triggered by untrusted contract/device data, consistent with CWE-918, matching the required "paired device" attacker surface.

### Likelihood Explanation
Any device that can pair with the victim (as required for any arbiter-mediated contract) can send an `arbiter_contract_offer`/appeal flow naming an `arbiter_address` whose hub is attacker-controlled (self-hosted hub), guaranteeing the returned "arbstore URL" is fully attacker-chosen. No additional privilege beyond normal device pairing/contract negotiation is required, so likelihood is high once the victim engages with an arbiter-contract feature.

### Recommendation
- Validate URLs returned by `hub/get_arbstore_url`/`hub/get_arbstore_url_by_address` before fetching: enforce `https://` scheme, resolve and reject requests to private/loopback/link-local/reserved IP ranges, and consider requiring the ArbStore host to match a known allow-list or be attested by a trusted arbiter registry rather than trusted verbatim from any hub.
- Apply the same validation uniformly in `arbiters.js` (`requestInfoFromArbStore`, `getArbstoreInfo`) and `arbiter_contract.js` (`httpRequest`, `appeal`, `getAppealFee`, `getArbstoreAddresses`).
- Add request timeouts and response size limits to reduce the utility of the primitive as a scanning oracle.

### Proof of Concept
1. Attacker runs a hub that responds to `hub/get_arbstore_url` for address `ARB_ADDR` with `http://127.0.0.1:28080/admin` (or any internal target).
2. Attacker pairs with the victim device and sends an `arbiter_contract_offer` (via `arbiter_contract.store`) naming `arbiter_address = ARB_ADDR`.
3. When the victim wallet looks up arbiter info (`arbiters.getInfo`/`getArbstoreInfo`) or later performs `appeal`/`getAppealFee`, it calls `device.requestFromHub("hub/get_arbstore_url", ARB_ADDR, ...)` against the attacker's hub, receives the malicious URL, and then executes `http.get(url)` / `http.request(url, ...)` [1](#0-0) [8](#0-7)  — resulting in a server-side request from the victim node to the attacker-chosen internal endpoint.

### Citations

**File:** arbiters.js (L16-30)
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

**File:** arbiters.js (L60-79)
```javascript
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

**File:** arbiter_contract.js (L357-409)
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
