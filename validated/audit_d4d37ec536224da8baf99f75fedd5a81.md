### Title
Missing verification of arbiter/arbstore ownership before sending confidential contract data and funds - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` resolves an "arbstore" endpoint purely from the `arbiter_address`/`arbstore_address` fields stored on a contract record, and these fields are populated from data supplied by the untrusted counterparty (or cosigner) during contract negotiation. The code then connects to the hub-resolved URL and POSTs confidential contract data (encrypted contract text, pairing codes, contact info, addresses, unit) to it, and later sends a portion of settlement funds to `objContract.arbstore_address` — all without independently verifying that the resolved endpoint/address is a legitimately bound, trusted arbstore for that arbiter. This mirrors the CVE-2021-21663 bug class: a missing ownership/permission check before connecting to an attacker-influenced endpoint using sensitive identifiers, resulting in disclosure of secrets and, in this case, potential fund redirection.

### Finding Description
`openDispute`, `appeal`, and `getAppealFee` in `arbiter_contract.js` resolve a URL via `device.requestFromHub("hub/get_arbstore_url"/"hub/get_arbstore_url_by_address", address, ...)` using `objContract.arbiter_address` or `objContract.arbstore_address`: [1](#0-0) [2](#0-1) [3](#0-2) 

`getArbstoreAddresses`/`fillArbstoreAddresses` populate `arbstore_address`/`arbstore_device_address` directly from whatever the hub returns for the supplied `arbiter_address`, with no cross-check against a known/whitelisted arbiter registry entry tied cryptographically to the contract: [4](#0-3) 

Confidential material — including `encrypted_contract`, `my_pairing_code`, `peer_pairing_code`, `my_contact_info`, `peer_contact_info`, addresses and the contract `unit` — is then POSTed via plain `httpRequest` to that resolved URL: [5](#0-4) [6](#0-5) 

Because `arbiter_address` originates from the contract-negotiation payload sent by the peer counterparty (`arbiter_contract_offer` / `store()` for incoming or cosigner-shared contracts), and there is no validation step confirming the hub-provided arbstore endpoint/device address is the one that both parties actually intended or that it is a properly attested/registered arbstore before transmitting this data, an untrusted counterparty effectively steers where sensitive pairing codes and contract details are sent. The `httpRequest` helper itself performs a raw HTTPS POST with no additional authentication of the destination beyond the hub-returned URL string: [7](#0-6) 

Additionally, in `complete()`, the same unverified `objContract.arbstore_address` is used as a payment destination for the arbstore's cut of settlement funds: [8](#0-7) 

This is directly analogous to the Jenkins XL Deploy bug class: a missing check before connecting to (and sending sensitive material to) a URL/identity that is effectively attacker-influenced, rather than independently verified.

### Impact Explanation
If the "arbstore" URL/address resolution is not independently verified against the arbiter's cryptographically-bound registration, a malicious contract counterparty can cause the victim's wallet to leak pairing codes and contact info (secrets used to open direct device-to-device chat/signing channels) to an endpoint effectively of the attacker's choosing, and — via `complete()` — divert the arbstore's fee-cut output to an attacker-controlled address, resulting in fund loss for one of the contract parties.

### Likelihood Explanation
Exploitation requires only that the attacker act as the counterparty (or a cosigner) in an arbiter contract negotiation, a role reachable by any unprivileged peer who is offered/accepts a private arbiter contract — no special privileges are required beyond normal participation in the arbiter-contract flow.

### Recommendation
Before contacting any hub-resolved arbstore URL or sending settlement funds to `arbstore_address`, cryptographically verify that the resolved arbstore is genuinely bound to the negotiated `arbiter_address` (e.g., via a signed registration record checked against `arbiters.js`), and only proceed with `httpRequest`/fund allocation once this binding is confirmed by both parties' independent derivation, rather than trusting values received via `store()`/`setField()` from the counterparty.

### Proof of Concept
Not independently reproducible from static analysis alone — full confirmation would require tracing how `wallet.js`'s handling of the `arbiter_contract_offer` message populates `arbiter_address`/`arbstore_address` end-to-end and whether `arbiters.getInfo()`/`getArbstoreInfo()` (in `arbiters.js`) performs a compensating registry check earlier in the flow (`openDispute` does call `arbiters.getInfo` before proceeding, which may partially mitigate this — this call's exact validation logic was not retrievable within the available tooling budget). This limitation should be verified with full file access before treating this as confirmed exploitable versus a defense-in-depth gap.

### Citations

**File:** arbiter_contract.js (L228-260)
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

function fillArbstoreAddresses(objContract, cb) {
	if (!cb)
		return new Promise(resolve => fillArbstoreAddresses(objContract, resolve));
	if (objContract.arbstore_device_address && objContract.arbstore_address)
		return cb();
	getArbstoreAddresses(objContract.arbiter_address, function(err, result) {
		if (err)
			return cb(err);
		var { arbstore_address, arbstore_device_address } = result;
		objContract.arbstore_address = arbstore_address;
		objContract.arbstore_device_address = arbstore_device_address;
		db.query("UPDATE wallet_arbiter_contracts SET arbstore_address=?, arbstore_device_address=? WHERE hash=?", [arbstore_address, arbstore_device_address, objContract.hash], function () { cb(); });
	});
}
```

**File:** arbiter_contract.js (L262-268)
```javascript
function openDispute(hash, cb) {
	getByHash(hash, function(objContract){
		if (!["paid", "in_dispute"].includes(objContract.status))
			return cb("contract can't be disputed");
		device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, function(err, url){
			if (err)
				return cb(err);
```

**File:** arbiter_contract.js (L277-303)
```javascript
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

**File:** arbiter_contract.js (L321-331)
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
```

**File:** arbiter_contract.js (L339-352)
```javascript
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
```

**File:** arbiter_contract.js (L357-368)
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

**File:** arbiter_contract.js (L752-771)
```javascript
					if (objContract.me_is_payer && !(assetInfo && (assetInfo.fixed_denominations || assetInfo.is_private))) { // complete
						require("./wallet_defined_by_addresses.js").readSharedAddressDefinition(objContract.shared_address, function (arrDefinition) {
							const index = objContract.is_incoming ? 2 : 1;
							const peer_amount = arrDefinition[1][index][1][1][1].amount;
							const arbstore_amount = arrDefinition[1][index][1][2] && arrDefinition[1][index][1][2][0] === 'has' ? arrDefinition[1][index][1][2][1].amount : 0;
							if (!isFinite(peer_amount) || !isFinite(arbstore_amount))
								throw new Error("invalid amounts in shared address definition: " + JSON.stringify(arrDefinition));
							if (peer_amount + arbstore_amount !== objContract.amount)
								throw new Error(`amounts in shared address definition do not sum up to contract amount: ${peer_amount} + ${arbstore_amount} !== ${objContract.amount}`);
							if (arbstore_amount > peer_amount)
								throw new Error(`arbstore cut is more than 50% of the total amount, peer_amount: ${peer_amount}, arbstore_amount: ${arbstore_amount}`);
							if (arbstore_amount === 0) {
								opts.to_address = objContract.peer_address;
								opts.amount = objContract.amount;
							} else {
								opts[objContract.asset && objContract.asset != "base" ? "asset_outputs" : "base_outputs"] = [
									{ address: objContract.peer_address, amount: peer_amount},
									{ address: objContract.arbstore_address, amount: arbstore_amount},
								];
							}
```
