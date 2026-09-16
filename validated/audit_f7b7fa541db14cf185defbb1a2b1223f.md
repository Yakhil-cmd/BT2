### Title
Server-Side Request Forgery via attacker-controlled arbiter contract `arbiter_address` → arbstore URL lookup - (File: `arbiter_contract.js`)

### Summary
A paired-device counterparty in an arbiter contract can name an arbitrary address as the contract's `arbiter_address`. When the victim wallet later performs any arbiter-related action on that contract (`openDispute`, `appeal`, `getAppealFee`), it asks its own hub for the "arbstore URL" bound to that address and then issues an outbound HTTP(S) request — including a JSON payload with contract details — to whatever URL is returned, with no host/scheme validation or SSRF protections.

### Finding Description
An incoming contract offer (`arbiter_contract_offer` device message) is persisted verbatim via `store()`, including the attacker-supplied `arbiter_address` field [1](#0-0) . This value is never checked to belong to a real/known arbiter — it is simply an address chosen by the peer proposing the contract.

Later, when the local user calls `openDispute`, `appeal`, or `getAppealFee` on that contract, the code resolves the arbstore URL for `objContract.arbiter_address` via the user's own hub and then performs an outbound HTTP request to that URL without validating it is a legitimate external ArbStore host: [2](#0-1) [3](#0-2) 

The actual request construction in `httpRequest()` performs no scheme/host allow-listing, no private-IP/loopback/link-local blocking, and blindly parses and dials whatever `host` string is supplied: [4](#0-3) 

The same unguarded pattern exists in `arbiters.js`, whose only check is `isNonemptyString(url)` — it does not restrict the URL's scheme or target IP range, and still performs GET requests to it: [5](#0-4) [6](#0-5) 

Since the attacker only needs to control (or collude with) the `hub/get_arbstore_url` answer for the `arbiter_address` they nominate in the contract offer — something achievable by simply registering their own arbiter address's arbstore URL as any hub-reachable value (e.g. `http://169.254.169.254`, `http://127.0.0.1:<internal-port>`, or an internal service address) — the victim wallet is coerced into making the outbound request automatically as soon as it acts on the contract (opening a dispute or appeal).

### Impact Explanation
The forged request is a POST carrying the full contract payload — including `my_address`, `peer_address`, encrypted contract text, pairing codes, and (for private assets) the private `amount`/`asset` — to an attacker-chosen internal or otherwise restricted host [7](#0-6) . This can be used to:
- Reach internal-only network services (metadata endpoints, admin APIs, internal microservices) reachable from the victim's node/wallet host, driven entirely by a value chosen by an untrusted paired-device counterparty.
- Exfiltrate sensitive contract/pairing data to an internal endpoint via the POST body.
- Trigger unintended side effects on internal services that accept POST/GET requests with attacker-influenced paths (`/api/dispute/new`, `/api/appeal/new`, `/api/get_appeal_fee`, `/api/arbiter/<address>`, `/api/get_info`).

This matches the class of impact from the cited Dify CVE-2024-11822 (unauthenticated internal network access/exfiltration via an unvalidated endpoint parameter), reframed onto ocore's arbiter-contract flow where the "endpoint" is indirectly supplied by an untrusted counterparty via the `arbiter_address` they pick.

### Likelihood Explanation
Any device paired with the victim (a normal contract counterparty) can send an `arbiter_contract_offer` naming any address as arbiter — no on-chain validation or arbiter registry membership check is performed before storage [8](#0-7) . The victim only needs to interact with that contract (open a dispute, request an appeal, or query the appeal fee) — normal, expected user actions for a disputed contract — to trigger the outbound request. No special privileges are required by the attacker beyond being a wallet pairing/chat counterparty.

### Recommendation
- Validate that `arbiter_address` corresponds to a genuinely registered/known arbiter (e.g., cross-check against a trusted arbiter list or the hub-verified `arbiters.getArbstoreInfo` result) before allowing contract creation/acceptance to reference it.
- In `httpRequest()` and `requestInfoFromArbStore()`, validate the resolved URL's scheme (only `https:`) and resolve/verify the target host is not a private, loopback, link-local, or metadata-service IP range before connecting (standard SSRF mitigations: DNS-rebinding-safe IP allow-listing, blocking RFC1918/169.254.0.0/16/::1, etc.).
- Avoid including private/sensitive contract fields (amounts, asset ids for private assets, pairing codes) in requests to URLs that are not strongly authenticated as belonging to a trusted, pre-approved arbstore.

### Proof of Concept
1. Attacker (device B) pairs with victim (device A) and sends an `arbiter_contract_offer` where `arbiter_address` is an address the attacker controls and for which the attacker's hub will answer `hub/get_arbstore_url` with an internal URL, e.g. `http://169.254.169.254` or `http://127.0.0.1:6667` [9](#0-8) .
2. Victim's wallet stores the offer unmodified via `store()` [1](#0-0) .
3. Victim later calls `openDispute(hash, cb)` (a normal, user-initiated action for a contract believed to be in dispute).
4. `device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, ...)` returns the attacker-controlled internal URL [10](#0-9) .
5. `httpRequest(url, "/api/dispute/new", dataJSON, cb)` issues a POST containing contract data (including private asset/amount when applicable) directly to the internal URL, with no validation of `url`'s host/scheme [11](#0-10) [4](#0-3) .

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

**File:** arbiter_contract.js (L91-110)
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
```

**File:** arbiter_contract.js (L262-303)
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

**File:** arbiters.js (L51-80)
```javascript
function getArbstoreInfo(arbiter_address, cb) {
	if (!cb)
		return new Promise(function(resolve, reject){
			getArbstoreInfo(arbiter_address, function(err, info){
				if (err) return reject(err);
				resolve(info);
			});
		});
	if (arbStoreInfos[arbiter_address]) return cb(null, arbStoreInfos[arbiter_address]);
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
}
```
