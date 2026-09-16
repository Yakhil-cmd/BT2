### Title
Unbounded in-memory buffering of ArbStore HTTP responses causes OOM DoS - ([File: arbiter_contract.js], [File: arbiters.js])

### Summary
The arbiter-contract feature lets a wallet's private-payment counterparty propose a contract that names an `arbiter_address`. When the local wallet later resolves that arbiter's ArbStore endpoint and communicates with it (looking up arbiter info, fetching the ArbStore device address, opening a dispute, or filing an appeal), the HTTP response body is read into memory with no size bound, exactly mirroring the Traefik ForwardAuth `io.ReadAll` flaw.

### Finding Description
Two code paths accumulate an HTTP response body into a JS string with an unbounded `data += chunk` loop and no `Content-Length`/size check:

- `arbiters.js` `requestInfoFromArbStore()`, used by `getInfo()` and `getArbstoreInfo()`: [1](#0-0) 

- `arbiter_contract.js` `httpRequest()`, used by `getArbstoreAddresses()`, `openDispute()`, `appeal()`, and `getAppealFee()`: [2](#0-1) 

The URL that both functions fetch (`http.get(url, ...)` / `httpRequest(url, ...)`) is derived from `objContract.arbiter_address`, which is set on the **incoming, peer-supplied** contract object and stored verbatim by `store()` without any restriction on which arbiter/ArbStore it points to: [3](#0-2) 

`getArbstoreAddresses()` resolves that arbiter address to a URL via the hub and then immediately performs an unbounded read against it: [4](#0-3) 

and `openDispute()` / `appeal()` invoke `fillArbstoreAddresses()` → `getArbstoreAddresses()` → `httpRequest()` automatically as part of normal dispute/appeal flow, then a second unbounded `httpRequest()` call for the actual dispute/appeal payload response: [5](#0-4) 

Because `arbiter_address` in the contract offer is fully attacker-controlled (an adversarial private-payment counterparty can name any arbiter, including one they register/control themselves so the hub returns an ArbStore URL under their control), the counterparty can arrange for the victim wallet to connect to a malicious ArbStore server that streams an effectively infinite/oversized HTTP response. Neither `requestInfoFromArbStore` nor `httpRequest` applies `io.LimitReader`-equivalent bounding (no max body size, no `Content-Length` enforcement), so Node.js will keep concatenating chunks into the `data` string until the process runs out of memory and is killed.

### Impact Explanation
A successful attack crashes the victim's wallet/node process via unbounded memory allocation, which is a denial of service and matches CWE-770 (Allocation of Resources Without Limits). This can be triggered purely through the private-payment/contract-arbitration flow — no privileged access or malicious hub/node behavior is required, only a malicious counterparty in a peer-to-peer arbiter contract negotiation, which is explicitly in-scope reachability (private-payment counterparty).

### Likelihood Explanation
The counterparty fully controls the `arbiter_address` field of a contract offer they send via `device.sendMessageToDevice(..., "arbiter_contract_offer", ...)`, and once the victim accepts the contract (or even at dispute/appeal time) the wallet automatically issues unbounded HTTP fetches to the resolved ArbStore URL with no user confirmation of response size. Setting up an attacker-controlled arbiter/ArbStore endpoint that streams an oversized chunked response is straightforward, making exploitation practical whenever a victim wallet engages in arbiter-mediated contracts with an untrusted counterparty.

### Recommendation
Apply a hard cap on ArbStore/auth-style response bodies in both `arbiters.js` `requestInfoFromArbStore()` and `arbiter_contract.js` `httpRequest()`: track accumulated byte length on each `data` event and abort/destroy the response (and surface an error) once a fixed limit (e.g. a few hundred KB, sufficient for JSON arbiter-info/dispute responses) is exceeded, rather than unconditionally concatenating chunks until `end`.

### Proof of Concept
1. Attacker (counterparty) proposes an `arbiter_contract_offer` whose `arbiter_address` corresponds to an arbiter entry the attacker controls, such that `hub/get_arbstore_url` for that address resolves to an ArbStore server operated by the attacker.
2. Victim's wallet accepts/handles the contract normally.
3. Victim (or the wallet automatically) calls `openDispute()`/`appeal()`/`getInfo()`/`getArbstoreInfo()`, causing `arbiter_contract.js`'s `getArbstoreAddresses()`/`httpRequest()` or `arbiters.js`'s `requestInfoFromArbStore()` to issue an HTTP(S) request to the attacker's ArbStore URL.
4. Attacker's server responds with `Transfer-Encoding: chunked` and streams unbounded data (analogous to the PoC in the Traefik advisory).
5. The victim process's memory grows unbounded in the `resp.on('data', ...)` handlers in [6](#0-5)  and [7](#0-6)  until the process is OOM-killed, causing denial of service.

### Citations

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
