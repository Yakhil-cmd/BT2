### Title
Attacker-controlled `arbiter_address` in an Arbiter Contract offer causes SSRF and exfiltration of pairing secrets / contract data via unvalidated `httpRequest()` - (File: `arbiter_contract.js`)

### Summary
`arbiter_contract.js` accepts a private-payment counterparty's `arbiter_contract_offer` device message and persists the peer-supplied `arbiter_address` verbatim via `store()`, without validating that it is a legitimate address bound to a genuine ArbStore registration. When the victim later interacts with the contract (`openDispute`, `appeal`, `getAppealFee`, `arbiters.getInfo`/`getArbstoreInfo`), the wallet resolves a URL for that attacker-influenced address and blindly issues an HTTP request to it via `httpRequest()`/`requestInfoFromArbStore()`, which builds the request target with `url.parse(host)` and no scheme/host allow-listing, then sends contract secrets (permanent pairing code containing `pairing_secret`, contact info, encrypted contract payload) to whatever host the resolved URL points to. This mirrors the GuardDog SSRF/credential-exfiltration pattern: an attacker-influenced hostname is trusted blindly and sensitive secrets are sent to it over an unauthenticated/uncontrolled request.

### Finding Description
- `store()` in `arbiter_contract.js` (called when a peer sends `arbiter_contract_offer`) inserts the peer-controlled `objContract.arbiter_address` directly into `wallet_arbiter_contracts` with no `ValidationUtils.isValidAddress` check visible in the surrounding code path. [1](#0-0) 
- Later flows (`openDispute`, `appeal`, `getAppealFee`) take `objContract.arbiter_address` from the stored row and pass it to `device.requestFromHub("hub/get_arbstore_url", address, ...)` to resolve a URL, then call `httpRequest(url, ...)` which builds the HTTP request purely from `url.parse(host)` with no host/scheme validation: [2](#0-1) [3](#0-2) [4](#0-3) 
- `arbiters.js` has the same pattern: it only checks `isNonemptyString(url)` before dispatching the request, with no restriction on protocol or destination host, and sends the request via plain `https.get`/`http.get`: [5](#0-4) 
- The data sent to this unvalidated URL in `openDispute`/`appeal` includes the victim's **permanent pairing code** (`device_pubkey + "@" + hub + "#" + pairing_secret`), contact info, and the encrypted contract payload — sensitive data analogous to the `GH_TOKEN` exfiltrated in the GuardDog case: [6](#0-5) 

Unlike `network.js`'s `isValidWsUrl()`, which explicitly rejects URLs containing embedded credentials and restricts protocol/scheme for peer connection URLs, no equivalent hardening exists for the ArbStore URL resolution/request path: [7](#0-6) 

Because the URL resolution is keyed by an address that originates from the untrusted contract offer (an unprivileged private-payment counterparty), and the resulting request is dispatched with no destination validation, an attacker who proposes a contract with a crafted `arbiter_address` (that they can arrange to have registered on a hub, or otherwise resolved to an attacker-controlled endpoint) can redirect the victim's wallet HTTP traffic — including pairing secrets — to an arbitrary host.

### Impact Explanation
This qualifies as a concrete impact class allowed by the rules: theft of the victim's device pairing secret (`pairing_secret`) constitutes credential exfiltration comparable to the `GH_TOKEN` theft in the original advisory, and enables the attacker to impersonate/pair as the victim's device or hijack the arbiter-contract dispute flow, potentially leading to loss of funds held in the arbiter/shared-address contract (fund loss for a private-payment counterparty). It also creates an SSRF vector letting a remote peer cause the victim's node to make arbitrary outbound HTTP requests carrying wallet metadata.

### Likelihood Explanation
Medium-High: any unprivileged device peer can initiate an arbiter contract offer and choose the `arbiter_address`; the victim only needs to accept/proceed with a normal contract lifecycle action (open dispute, appeal, or fetch arbiter info) to trigger the vulnerable request path. No special privileges, mining power, or hub compromise are required beyond controlling the contract offer content.

### Recommendation
- Validate `arbiter_address` (and any resolved ArbStore URL) strictly before use: enforce `ValidationUtils.isValidAddress()` on `arbiter_address` at `store()`/ingestion time, and validate the resolved URL's scheme/host (e.g., require `https:`, reject URLs with embedded credentials, reject private/loopback IP ranges) similarly to `isValidWsUrl()` in `network.js`.
- Do not include pairing secrets or other sensitive payloads in requests to externally resolved URLs unless the destination has been authenticated (e.g., pinned to a known ArbStore public key or TLS certificate) analogous to how GitHub host/hostname pinning is recommended in the original advisory's fix.
- Apply the same allow-listing/validation logic uniformly across `arbiter_contract.js` and `arbiters.js` HTTP call sites.

### Proof of Concept
1. Attacker (device peer) sends an `arbiter_contract_offer` with `arbiter_address` set to an address the attacker controls/registers as an "arbiter" on some hub, pointing its ArbStore URL to an attacker-controlled server (or an internal/loopback address reachable by the victim).
2. Victim accepts and later calls `openDispute()`/`appeal()`/`getAppealFee()` on the contract.
3. `device.requestFromHub("hub/get_arbstore_url", arbiter_address, ...)` resolves to the attacker's URL.
4. `httpRequest(url, "/api/dispute/new", dataJSON, cb)` sends contract data including `my_pairing_code` (containing `pairing_secret`) to the attacker's server.
5. Attacker's server logs the request and captures the victim's pairing secret and contract details. [2](#0-1)

### Citations

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

**File:** arbiter_contract.js (L321-376)
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

**File:** network.js (L745-763)
```javascript
function isValidWsUrl(url) {
	try {
		const { protocol, hash, username, password } = new URL(url);
		if (hash)
			return false;
		if (url.includes('#')) // empty trailing hash
			return false;
		if (username || password) // no legitimate peer url needs credentials
			return false;
		if (!['wss:', 'ws:'].includes(protocol))
			return false;
		if (conf.WS_PROTOCOL === 'wss://' && protocol !== 'wss:')
			return false;
		return true;
	}
	catch {
		return false;
	}
}
```
