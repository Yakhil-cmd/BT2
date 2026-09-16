### Title
Unbounded HTTP response buffering when contacting an attacker-controlled ArbStore server leads to wallet memory exhaustion - ([File: arbiters.js])

### Summary
`arbiters.js` and `arbiter_contract.js` implement HTTP clients that talk to an "ArbStore" server associated with an arbiter address used in arbiter contracts (a wallet/contract feature reachable by any peer who proposes or interacts in such a contract). Both HTTP response handlers accumulate the entire response body into a single in-memory string with `data += chunk`, with no length cap, before calling `JSON.parse`. This is the same bug class as CWE-789/GHSA-w2jh-77fq-7gp8: an unbounded read of an HTTP response body into memory.

### Finding Description
`requestInfoFromArbStore` in `arbiters.js` does: [1](#0-0) 
and is called from `getInfo`/`getArbstoreInfo`, both of which resolve the ArbStore `url` from a `hub/get_arbstore_url` lookup keyed by an `arbiter_address`: [2](#0-1) 

Similarly, `httpRequest` in `arbiter_contract.js` performs the same unbounded accumulation pattern: [3](#0-2) 

It is invoked from several contract-lifecycle functions — `getArbstoreAddresses`, `openDispute`, `appeal`, and `getAppealFee` — all of which are driven by `arbiter_address`/`arbstore_address` fields stored on a `wallet_arbiter_contracts` row: [4](#0-3) [5](#0-4) 

An arbiter contract is created and exchanged between two devices via `createAndSend`/`arbiter_contract_offer` messages, where the `arbiter_address` is a value chosen by one of the peers and propagated into the receiving wallet's local contract record: [6](#0-5) 
Anyone can register an address as an "arbiter" on a hub and set an arbitrary ArbStore URL for it (the URL is returned verbatim by `hub/get_arbstore_url`); nothing in `arbiters.js` or `arbiter_contract.js` validates or bounds the size of the HTTP response coming back from that URL. Consequently, a peer who proposes (or is offered) a contract naming an attacker-controlled arbiter/ArbStore, or simply an attacker who registers themselves as an arbiter that a victim later interacts with (checking appeal fee, opening a dispute, fetching arbiter/arbstore info, deriving the shared address which calls `arbiters.getArbstoreInfo`), causes the victim wallet process to issue an HTTP(S) request to attacker infrastructure and buffer the *entire* response body in memory with no size limit before parsing it as JSON.

### Impact Explanation
An attacker-controlled ArbStore endpoint can return an arbitrarily large HTTP response body (e.g., gigabytes) in response to `/api/arbiter/<address>`, `/api/get_info`, `/api/get_appeal_fee`, `/api/dispute/new`, `/api/appeal/new`, or `/api/get_device_address`. Because the response is buffered unboundedly via string concatenation (`data += chunk`) rather than streamed with a cap, this can exhaust the victim wallet's Node.js heap, crashing the wallet/light-node process (denial of service) whenever the victim's wallet interacts with an arbiter contract that references the attacker's arbiter/ArbStore address — a normal, expected wallet action (checking appeal fee, opening a dispute, deriving/paying a shared contract address) rather than a privileged or hub-level operation.

### Likelihood Explanation
Likelihood is limited by the need for user interaction: the victim must actually engage with an arbiter contract (accept an offer or otherwise reference an arbiter address) whose ArbStore endpoint is attacker-controlled — self-registration as an arbiter is unrestricted, and the flow (`openDispute`, `appeal`, `getAppealFee`, `getArbstoreInfo`/`deriveSharedAddress`) is reached through ordinary wallet/contract usage, not through privileged operator actions. This matches the "Medium" severity/likelihood profile of the referenced advisory (network-reachable but requiring the victim to interact with attacker-chosen server infrastructure).

### Recommendation
- Cap the maximum accumulated response size in `requestInfoFromArbStore` (arbiters.js) and `httpRequest` (arbiter_contract.js), aborting/destroying the response stream once a reasonable limit (e.g., a few hundred KB) is exceeded, mirroring the OpAMP client fix (limit responses to a bounded size such as 128KB).
- Enforce the same cap via `Content-Length` pre-check where available, and always enforce it during streaming regardless of a (possibly absent or falsified) `Content-Length` header.
- Apply the fix uniformly to both `arbiters.js:requestInfoFromArbStore` and `arbiter_contract.js:httpRequest`.

### Proof of Concept
1. Attacker registers an arbiter address on a hub (`hub/register_arbiter` or equivalent) and sets `hub/get_arbstore_url` to point to an HTTP(S) server the attacker controls.
2. Attacker (as peer) sends an `arbiter_contract_offer` device message to the victim naming this arbiter address, or otherwise gets the victim's wallet to interact with a contract referencing this arbiter (e.g., victim calls `getAppealFee`, `openDispute`, or `deriveSharedAddress`, which calls `arbiters.getArbstoreInfo`).
3. Victim wallet resolves the ArbStore URL via `hub/get_arbstore_url` and issues an HTTP(S) request to the attacker's server (`arbiters.js:requestInfoFromArbStore` or `arbiter_contract.js:httpRequest`).
4. Attacker's server responds with an HTTP 200 and streams an extremely large (e.g., multi-GB) response body, optionally never closing the connection.
5. The victim's `data += chunk` loop accumulates the entire body in memory with no bound, exhausting the Node.js heap and crashing/hanging the wallet process — a denial of service against the victim's wallet.

### Citations

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
