Found it: `arbiter_contract.js`'s `deriveSharedAddress` function bakes the ArbStore's `cut` percentage — fetched live via `arbiters.getArbstoreInfo` — directly into the shared address definition amounts, and this cut can change between when the contract terms are agreed and when the shared address/definition is actually derived and posted on-chain.

### Title
ArbStore cut can change between contract negotiation and shared-address derivation, causing a party to receive less than agreed - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js`'s `deriveSharedAddress()` fetches the ArbStore's fee `cut` via `arbiters.getArbstoreInfo()` at the moment the shared address definition is built, and hard-codes `Math.floor(contract.amount * (1 - arbstoreInfo.cut))` into the on-chain spending condition [1](#0-0) . The `cut` value is supplied by a third party (the ArbStore operator) fetched over HTTP and cached only in-memory, with no binding to the value that was in effect when the two contract parties agreed on `contract.amount`/terms [2](#0-1) .

### Finding Description
When two parties agree to an arbiter contract, the contract terms (amount, asset, arbiter) are fixed and hashed at negotiation time [3](#0-2) . However, the actual payment split enforced on-chain is computed later, when `createSharedAddressAndPostUnit` → `deriveSharedAddress` runs and queries the ArbStore for its current `cut` value [4](#0-3) , [2](#0-1) . This value is not part of the contract that was cryptographically committed to (hashed) by both parties beforehand; it is fetched fresh (or from a short-lived in-process cache `arbStoreInfos`) at address-derivation time. An ArbStore operator (or anyone able to influence the HTTP response, e.g. a compromised/malicious ArbStore) can therefore change `cut` between when the offeror and acceptor agree to the contract and when the shared address is actually derived and posted, altering the amounts baked into the `has output` conditions of the resulting address definition [5](#0-4) . Since the definition (and therefore the enforced split between `peer_address`/`offeror_address`/`arbstoreInfo.address`) is derived independently by each party's own node at send/verify time, a change in `cut` value results in a different definition than what was implicitly agreed, silently diverting more of the funds to the ArbStore (or the counterparty) than was consented to.

### Impact Explanation
If the ArbStore raises its `cut` between contract agreement and shared-address posting, the payer ends up sending, and the payee ends up receiving, an amount that deviates from the agreed contract terms, with the difference diverted to the ArbStore address baked into the definition. Because the split is enforced by the `has output` conditions inside the immutable shared-address definition, once posted the funds move according to the new (unexpectedly higher) cut with no recourse — a concrete, unauthorized redirection of funds away from a contract party, analogous to the referenced fee front-running class of bug.

### Likelihood Explanation
This requires control over, or compromise of, the ArbStore HTTP endpoint queried by `getArbstoreInfo`/`getInfo` [6](#0-5) , which the two contracting parties are already trusting as a semi-privileged third party for their transaction (analogous to a "market owner" in the referenced bug). There is no timelock, no binding of `cut` to the value seen when the contract text/hash was agreed, and no re-validation that the derived amounts match what the parties expected before the shared address is created and payment sent.

### Recommendation
Capture and persist the ArbStore `cut` value at the time the contract is agreed/hashed (include it in the signed contract content or `getHash()` computation), and validate at `deriveSharedAddress`/`complete` time that the currently fetched `cut` matches the value the parties committed to; refuse to proceed (or re-negotiate) if it has changed.

### Proof of Concept
1. Alice and Bob negotiate an arbiter contract for `amount = 100000` bytes via `arbiter_contract_offer`, with ArbStore currently advertising `cut = 0.01` (visible to both parties at negotiation time, but not part of the hashed contract fields returned by `getHash()`).
2. The malicious/compromised ArbStore operator changes its `/api/get_arbstore_url` / `/api/get_info` response so `cut = 0.5` right before Alice calls `createSharedAddressAndPostUnit`.
3. `deriveSharedAddress()` calls `arbiters.getArbstoreInfo(contract.arbiter_address)`, retrieves `cut = 0.5`, and bakes `Math.floor(contract.amount * (1 - 0.5)) = 50000` as the amount payable to Bob, with the remaining 50000 conditioned to go to the ArbStore address, instead of the ~99000/1000 split both parties expected [5](#0-4) .
4. Alice's wallet signs and posts the payment per this definition; Bob receives far less than agreed, with no on-chain record of the originally agreed cut to dispute against.

### Citations

**File:** arbiter_contract.js (L454-522)
```javascript
function deriveSharedAddress(hash, bOfferor, cb) {
	getByHash(hash, function (contract) {
		const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
		const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
		const offeror_is_payer = bOfferor ? contract.me_is_payer : !contract.me_is_payer;
		const offeror_device_address = bOfferor ? device.getMyDeviceAddress() : contract.peer_device_address;
		const acceptor_device_address = bOfferor ? contract.peer_device_address : device.getMyDeviceAddress();
		arbiters.getArbstoreInfo(contract.arbiter_address, function(err, arbstoreInfo) {
			if (err)
				return cb(err);
			storage.readAssetInfo(db, contract.asset, function (assetInfo) {
				var arrDefinition =
					["or", [
						["and", [
							["address", offeror_address],
							["address", acceptor_address]
						]],
						[], // placeholders [1][1]
						[],	// placeholders [1][2]
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
					]];
				var isPrivate = assetInfo && assetInfo.is_private;
				var isFixedDen = assetInfo && assetInfo.fixed_denominations;
				var hasArbStoreCut = arbstoreInfo.cut > 0;
				if (isPrivate) { // private asset
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["in data feed", [[acceptor_address], "CONTRACT_DONE_" + contract.hash, "=", offeror_address]]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["in data feed", [[offeror_address], "CONTRACT_DONE_" + contract.hash, "=", acceptor_address]]
					]];
				} else {
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
							address: acceptor_address
						}]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer || isFixedDen || !hasArbStoreCut ? contract.amount : Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
							address: offeror_address
						}]
					]];
					if (!isFixedDen && hasArbStoreCut) {
						arrDefinition[1][offeror_is_payer ? 1 : 2][1].push(
							["has", {
								what: "output",
								asset: contract.asset || "base",
								amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
								address: arbstoreInfo.address
							}]
						);
					}
```

**File:** arbiter_contract.js (L578-592)
```javascript
function createSharedAddressAndPostUnit(hash, walletInstance, cb) {
	deriveSharedAddress(hash, true, function(err, arrDefinition, assocSignersByPath) {
		if (err)
			return cb(err);
		require("./wallet_defined_by_addresses.js").createNewSharedAddress(arrDefinition, assocSignersByPath, {
			ifError: function(err){
				cb(err);
			},
			ifOk: function(shared_address){
				setField(hash, "shared_address", shared_address, async function(contract) {
					const err = await fillArbstoreAddresses(contract);
					if (err)
						return cb(err);
					// share this contract to my cosigners for them to show proper ask dialog
					shareContractToCosigners(contract.hash);
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

**File:** wallet.js (L617-631)
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
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				if (![body.title, body.text, body.my_pairing_code].every(ValidationUtils.isNonemptyString))
					return callbacks.ifError("wrong required fields");
```
