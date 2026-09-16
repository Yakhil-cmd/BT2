Confirmed root cause: `arbiter_address` in `arbiter_contract_offer` and `arbiter_contract_shared` messages is validated only as a syntactically valid address (`ValidationUtils.isValidAddress`), never checked against any registry of legitimate arbiters. The offering peer (or any cosigner sharing the wallet) fully controls this value.

### Title
Attacker-Controlled Arbiter Address Leads to SSRF via Arbstore URL Lookup in Dispute/Appeal Flow - (File: arbiter_contract.js)

### Summary
`arbiter_contract.openDispute`, `appeal`, and `getAppealFee` resolve an "arbstore" HTTP(S) URL for the contract's `arbiter_address` via `device.requestFromHub("hub/get_arbstore_url", ...)` and then POST sensitive contract data directly to that URL with `httpRequest()`/`https.request()`. The `arbiter_address` value originates from an untrusted, unprivileged peer message (`arbiter_contract_offer`) or a cosigner message (`arbiter_contract_shared`), and is only checked for address format, not for being a legitimate/known arbiter.

### Finding Description
When a wallet receives an `arbiter_contract_offer` from a paired device, `wallet.js` validates `arbiter_address` only with `ValidationUtils.isValidAddress(body.arbiter_address)`: [1](#0-0) 
The contract, including the attacker-chosen `arbiter_address`, is then persisted via `arbiter_contract.store`. The same weak check applies to `arbiter_contract_shared`, sent by a cosigner on a shared wallet: [2](#0-1) 

Later, when the victim (the contract counterparty or a cosigner) opens a dispute, appeals, or fetches the appeal fee, the code resolves the arbstore URL for `objContract.arbiter_address` and performs an outbound HTTP(S) request to it, sending pairing codes, addresses, amounts, asset, and an encrypted contract package: [3](#0-2) [4](#0-3) [5](#0-4) 

The URL resolution itself goes through the hub (`hub/get_arbstore_url`), and `httpRequest`/`arbiters.requestInfoFromArbStore` build the request from the returned URL with no scheme/host allow-listing: [6](#0-5) [7](#0-6) 

Because `arbiter_address` is attacker-supplied and unrelated to whether it's a genuine, hub-vetted arbiter, an attacker who is simply a paired correspondent (offering party) or a cosigner on a shared wallet can steer the flow toward an arbiter address they control (registering themselves — or colluding with a malicious/compromised hub operator entry — as "arbstore" for that address), causing the victim node to make outbound HTTP requests carrying private contract/pairing/asset data to a URL of the attacker's choosing. This mirrors the CWE-918 SSRF pattern in the Jenkins Mattermost plugin, where a plugin blindly POSTs to a server/room specified by a party with limited privilege (`Overall/Read`), analogous here to an unprivileged paired-device/cosigner controlling the destination of outbound requests carrying contract data.

### Impact Explanation
An attacker acting as an unprivileged paired correspondent or wallet cosigner can cause the victim's node to send private, sensitive contract data (pairing codes for future device pairing, addresses, amounts, asset identifiers, and an encrypted contract blob) to an attacker-influenced endpoint reached via the hub's arbstore-URL indirection. Because pairing codes are leaked to an attacker-chosen destination, this could enable further device impersonation/pairing abuse, and in the appeal flow, `objContract.asset`/`amount` and party addresses are also exposed. This qualifies as unauthorized information exposure via SSRF that could culminate in device compromise/pairing hijack, fitting the "Medium" severity of the reported analog.

### Likelihood Explanation
Any user who accepts an incoming pairing request or is invited into an arbiter contract by a malicious peer, or is a cosigner on a multi-signature wallet with a malicious co-owner, can be targeted — no special privileges are needed beyond normal contract/dispute usage that the wallet already supports. The victim need only proceed with a dispute or appeal on a contract whose `arbiter_address` was supplied by the attacker.

### Recommendation
Do not trust `arbiter_address` supplied in `arbiter_contract_offer`/`arbiter_contract_shared` for driving outbound network requests without additional verification (e.g., requiring the arbiter to be present in a hub-curated/whitelisted arbiter directory, or requiring the local user to explicitly select/approve the arbiter/arbstore before any HTTP request is made). Additionally, validate that URLs returned by `hub/get_arbstore_url` match an expected scheme/host allow-list, and avoid sending private contract data (pairing codes, contact info) to arbstore endpoints that have not been independently confirmed as legitimate for the given `arbiter_address`.

### Proof of Concept
1. Attacker pairs with the victim's wallet as a normal correspondent device.
2. Attacker sends an `arbiter_contract_offer` message with `arbiter_address` set to an address the attacker controls and is registered (or can be registered) on the hub as having a malicious `arbstore` URL (e.g., `hub/get_arbstore_url` returns `https://attacker.example`), passing the format-only validation in `wallet.js` lines 617-627.
3. Victim accepts the offer, pays into the shared address, and later disputes or appeals (normal wallet UX flow).
4. `arbiter_contract.openDispute`/`appeal`/`getAppealFee` calls `device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, ...)`, obtains the attacker's URL, and POSTs contract data (`arbiter_contract.js` lines 262-375) including `my_pairing_code`, `peer_pairing_code`, addresses, amount, and asset to `https://attacker.example/api/dispute/new` (or `/api/appeal/new`, `/api/get_appeal_fee`), leaking this data to the attacker-controlled server.

### Citations

**File:** wallet.js (L617-627)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
```

**File:** wallet.js (L658-678)
```javascript
			case 'arbiter_contract_shared':
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.peer_pairing_code || !ValidationUtils.isPositiveInteger(body.amount))
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.arbiter_address) )
					return callbacks.ifError("either peer_address or address or arbiter_address or shared_address are not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address shared with your device");
						body.me_is_cosigner = true;
						arbiter_contract.store(body, true);
						callbacks.ifOk();
					}
				);
				break;
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
