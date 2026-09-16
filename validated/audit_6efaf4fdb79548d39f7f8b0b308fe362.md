### Title
SSRF via arbiter-controlled ArbStore URL in arbiter contract flow - (File: arbiter_contract.js)

### Summary
When a wallet user creates or interacts with an arbiter contract, ocore fetches the "ArbStore URL" associated with the counterparty's chosen `arbiter_address` from the hub and then makes outbound HTTP(S) requests to that URL without validating that it points to a legitimate, external ArbStore service. This mirrors CVE-2020-10791's root cause: a "test connection"-style feature performs outbound requests to an attacker-influenced endpoint (SSRF), except here the trigger is the arbiter-contract flow rather than a Grafana test-connection button.

### Finding Description
Any user can register as an "arbiter" (an address named in a contract's `arbiter_address` field) and have a URL registered with a hub as their ArbStore endpoint via the `hub/get_arbstore_url` protocol command. When a peer proposes/accepts/disputes/appeals a contract naming that arbiter, ocore code paths query this URL and issue raw HTTP/HTTPS requests to it:

- `arbiters.js` `getInfo()`/`getArbstoreInfo()` call `device.requestFromHub("hub/get_arbstore_url", address, ...)` and then perform `http.get(url+...)` in `requestInfoFromArbStore()` with only a non-empty-string check (`validationUtils.isNonemptyString(url)`), no scheme/host restriction. [1](#0-0) 
- `arbiter_contract.js` `getArbstoreAddresses()`, `openDispute()`, `appeal()`, and `getAppealFee()` all retrieve the same hub-supplied `url` and pass it into `httpRequest()`, which builds a raw `http.request` (actually `https` module aliased as `http`) to arbitrary `host`/`path` with POST data containing contract details (title, text, party names, contact info, and for private assets even `asset`/`amount`). [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

None of these validate that `url` resolves to a public, non-internal host (no protection against `http://127.0.0.1/...`, `http://169.254.169.254/...` metadata endpoints, internal LAN addresses, or unusual ports). The only check is `isNonemptyString(url)`. Since the arbiter is a role any device can claim in a peer-to-peer contract negotiation (the `arbiter_address`/its associated device registers its own ArbStore URL with a hub), a malicious counterparty acting as arbiter can point the ArbStore URL at an internal service, forcing the victim's node to issue outbound requests carrying contract-sensitive data (title, party names, contact info, and potentially asset/amount for private assets) whenever the victim disputes, appeals, or fetches appeal fees for a contract, or simply looks up arbiter info via `arbiters.getInfo`.

### Impact Explanation
This is a Server-Side Request Forgery: an attacker who is the counterparty's chosen (or malicious) arbiter can cause the victim node to make attacker-directed outbound HTTP requests, potentially reaching internal network services, cloud metadata endpoints, or triggering requests as part of a wider SSRF-to-RCE/pivot chain against internal infrastructure. It also leaks contract metadata and, for private assets, transaction amounts/asset ids to the attacker-controlled endpoint (`openDispute`/`appeal` include `asset`/`amount` in the POST body when the asset `is_private`). While this does not directly cause double-spend or fund loss, it satisfies the "node disagreement"/data-exfiltration-adjacent impact bar loosely, but more precisely it is unauthorized outbound requests and data exposure driven entirely by a value an unprivileged counterparty (the arbiter role) controls—consistent in bug class with the CVE (SSRF via unvalidated URL from a party-supplied configuration triggered by a "connection test"-like flow).

### Likelihood Explanation
Likelihood is moderate-to-high in the arbiter-contract feature context: any device can be selected/entered as `arbiter_address` in a contract, and the URL used for outbound requests is sourced from hub data associated with that arbiter (`hub/get_arbstore_url`), not validated for scheme or destination beyond non-emptiness. A user only needs to interact with a contract that names a malicious arbiter (open dispute, appeal, or simply request arbiter info) to trigger the outbound request. This does require the victim to engage with an arbiter contract naming the attacker as arbiter, which somewhat limits blast radius to users of that feature.

### Recommendation
Validate the ArbStore URL returned by the hub before making outbound requests: enforce `https://` scheme, disallow non-public/loopback/link-local/private IP ranges (RFC1918, 127.0.0.0/8, 169.254.0.0/16, etc.) and disallow non-standard ports if not expected, similar to SSRF mitigations. Centralize this validation in a single URL-vetting helper used by `arbiters.js` (`getInfo`, `getArbstoreInfo`, `requestInfoFromArbStore`) and `arbiter_contract.js` (`getArbstoreAddresses`, `openDispute`, `appeal`, `getAppealFee`, `httpRequest`) rather than relying on `validationUtils.isNonemptyString`.

### Proof of Concept
1. Attacker device registers itself as an arbiter with a hub, associating its `arbiter_address` with `hub/get_arbstore_url` value `http://169.254.169.254/latest/meta-data/` (or an internal service URL).
2. Attacker convinces or is chosen by a victim as the `arbiter_address` in an arbiter contract (`createAndSend` in `arbiter_contract.js`).
3. Victim disputes or appeals the contract, or independently calls `arbiters.getInfo(arbiter_address, cb)`.
4. The victim's node calls `device.requestFromHub("hub/get_arbstore_url", arbiter_address, ...)`, receives the attacker-controlled URL, and issues an outbound HTTP request via `httpRequest()`/`requestInfoFromArbStore()` to that URL, along with contract metadata in the POST body for dispute/appeal calls. [3](#0-2) [6](#0-5)

### Citations

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
