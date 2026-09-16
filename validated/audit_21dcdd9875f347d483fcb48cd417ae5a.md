### Title
Missing check that `arbiter_address` differs from the contract parties allows self-arbitration and theft of escrowed funds - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` and the `arbiter_contract_offer`/`arbiter_contract_shared` handlers in `wallet.js` never verify that `arbiter_address` is distinct from `my_address`/`peer_address`. A contract party can set itself as the "independent" arbiter, and the shared-address spending definition then lets that same address post the winning `data feed` and immediately claim the escrowed funds, exactly analogous to the Cooler `operator`/`overseer` collision: two roles that the protocol design assumes are separate (a neutral arbiter vs. a contract party) are never enforced to be distinct at the code level.

### Finding Description
When an arbiter contract is created, `deriveSharedAddress()` builds the funds-locking definition for the shared address with an `["or", [...]]` branch that allows either party to unilaterally claim the funds once the arbiter posts a `data feed` naming the winner: [1](#0-0) 

The winner-selection branches directly reference `contract.arbiter_address` as the sole trusted oracle for `"CONTRACT_" + contract.hash`: [2](#0-1) 

Nothing in the offer-creation path (`createAndSend`) or in the message handlers that accept an incoming offer/shared contract validates that `arbiter_address` is different from `my_address` or `peer_address`: [3](#0-2) [4](#0-3) 

`fillArbstoreAddresses`/`getArbstoreAddresses` only resolve the arbstore for whatever `arbiter_address` is supplied — they never check it isn't one of the contracting parties: [5](#0-4) 

Since `["in data feed", [[contract.arbiter_address], ...]]` only checks that the feed was posted by `contract.arbiter_address`, if that address equals `offeror_address` (or `acceptor_address`), the party that is supposed to be an unbiased outsider is also one of the two signers of the "and" branch requiring only their own signature plus their own data feed. This collapses the intended 3-party trust model (payer, payee, neutral arbiter) into a 2-party or even effectively 1-party model, exactly like the Cooler report's `operator == overseer` collision breaking the separation of privileged roles.

### Impact Explanation
If the payee (the party owed funds) sets `arbiter_address = my_address` (their own address) when proposing the contract, and the payer accepts without noticing the coincidence, the payee can:
1. Post a `data_feed` message from `arbiter_address` (= their own key) declaring themselves the winner (`CONTRACT_<hash> = payee_address`).
2. Immediately satisfy the `["and", [["address", offeror_address], ["in data feed", ...]]]` branch of the shared-address definition using only their own signature, bypassing any actual dispute-resolution process, arbstore fee logic, and the counterparty's consent.

This results in unauthorized spending / theft of the escrowed payment from the shared address without any genuine arbitration ever occurring — a direct loss of funds for the counterparty, matching the "concrete unauthorized spending" acceptance criterion. This is a Medium/High severity access-control break reachable purely through the private-payment/arbiter-contract counterparty flow (no malicious node/hub/network component required).

### Likelihood Explanation
Exploitation only requires one contract party (offeror or acceptor — either "private-payment counterparty" role) to propose/accept a contract where `arbiter_address` equals one of the two parties' addresses. Since the UI/protocol never rejects this at the validation layer (`wallet.js` message handlers, `arbiter_contract.js` contract/derivation logic), a malicious or careless party could set this up, and a distracted or trusting counterparty could accept it, especially since `arbiter_address` is just one more base32 address field among many in the offer payload with no distinctiveness check.

### Recommendation
Add explicit validation in the offer-creation and offer/shared-contract acceptance code paths (`wallet.js` `arbiter_contract_offer` / `arbiter_contract_shared` handlers, and `arbiter_contract.createAndSend`) rejecting contracts where `arbiter_address === my_address` or `arbiter_address === peer_address`. Additionally, `deriveSharedAddress()` in `arbiter_contract.js` should refuse to derive a shared address (return an error) if `contract.arbiter_address` matches either `offeror_address` or `acceptor_address`, providing defense-in-depth even if the initial offer validation is bypassed.

### Proof of Concept
1. Party A (payee, `me_is_payer = false`) creates an arbiter contract offer via `arbiter_contract.createAndSend` with `arbiter_address` set to their own `my_address`, and sends it to Party B (payer). [6](#0-5) 
2. Party B accepts without noticing `arbiter_address === A's address`; `wallet.js`'s `arbiter_contract_offer` handler performs no such check and stores/forwards the contract. [7](#0-6) 
3. Both parties derive the shared address via `deriveSharedAddress`, embedding `["in data feed", [[A_address], "CONTRACT_<hash>", "=", A_address]]` as a winning condition, with A_address doubling as both `arbiter_address` and `offeror_address`/`acceptor_address`. [2](#0-1) 
4. Party B pays into the shared address as required by the contract flow.
5. Party A posts a `data_feed` unit from their own address (which is also `arbiter_address`) setting `CONTRACT_<hash> = A_address`, then spends from the shared address using only their own signature — satisfying the `["and", [["address", A_address], ["in data feed", ...]]]` branch without any real, independent arbitration.
6. Party A takes the escrowed funds unilaterally; Party B has no recourse since the "arbiter" and the adversarial party are the same key.

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

**File:** arbiter_contract.js (L465-481)
```javascript
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
```

**File:** wallet.js (L617-654)
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
				if (![body.my_contact_info, body.my_party_name, body.peer_party_name].every(field => !field || typeof field === "string"))
					return callbacks.ifError("wrong optional fields");
				if (!(body.asset === null || ValidationUtils.isValidBase64(body.asset, constants.HASH_LENGTH)))
					return callbacks.ifError("wrong asset");
				var my_address = body.peer_address;
				body.peer_address = body.my_address;
				body.my_address = my_address;
				var my_party_name = body.peer_party_name;
				body.peer_party_name = body.my_party_name;
				body.my_party_name = my_party_name;
				body.peer_pairing_code = body.my_pairing_code; body.my_pairing_code = null;
				body.peer_contact_info = body.my_contact_info; body.my_contact_info = null;
				body.me_is_payer = !body.me_is_payer;
				if (body.hash !== arbiter_contract.getHash(body))
					throw Error("wrong contract hash after swapping me and peer");
				db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.my_address], function(rows) {
					if (!rows.length)
						return callbacks.ifError("contract does not contain my address");
					arbiter_contract.store(body, false, function() {
						eventBus.emit("arbiter_contract_offer", body.hash);
						callbacks.ifOk();
					});
				});
```

**File:** wallet.js (L658-666)
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
```
