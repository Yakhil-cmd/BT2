## Analog Vulnerability Found

### Title
Mass-Assignment of Trust-Critical Contract Fields (`status`, `shared_address`, `unit`) in Cosigner-Shared Arbiter Contract Message — ([File: arbiter_contract.js])

### Summary
The FlowiseAI bug is a mass-assignment flaw where a client-supplied JSON body is persisted verbatim into a database record, letting an attacker overwrite server-controlled fields (`workspaceId`) that should never be client-writable. The ocore analog is in the arbiter-contract subsystem: when a paired cosigner device sends an `arbiter_contract_shared` message, the wallet blindly inserts attacker-supplied `status`, `shared_address`, and `unit` fields into `wallet_arbiter_contracts` without any cryptographic verification, even though these are the exact fields that later gate a real-money payment.

### Finding Description
`wallet.js` handles the `arbiter_contract_shared` message (sent by a cosigner device) as follows: [1](#0-0) 

The only authorization check performed is that `from_address` is a registered cosigner device for `body.my_address` — it does **not** validate `body.status`, `body.shared_address`, or `body.unit` in any way, and simply calls `arbiter_contract.store(body, true)`.

`store()` then persists these attacker-controlled fields directly, with no whitelist enforcement or default override, whenever `bFromCosigner` is true: [2](#0-1) 

Critically, `status` is taken straight from `objContract.status` (i.e., attacker-controlled `body.status`) instead of being forced to `status_PENDING`, and `shared_address`/`unit` are inserted as-is if present in the payload. None of `status`, `shared_address`, or `unit` are part of the contract hash computed by `getHashSrc`/`getHash`: [3](#0-2) 

So an attacker can freely set `status`/`shared_address`/`unit` to arbitrary values while still producing a hash that passes the `getHash(body)` check in the caller (since that check only covers title/text/dates/addresses/amount/asset).

Contrast this with the legitimate path, `handleReceivedSharedAddress`, which re-derives the expected shared address cryptographically from the contract parties and rejects any mismatch before storing it: [4](#0-3) 

The `arbiter_contract_shared` path bypasses this verification entirely — it is the mass-assignment analog of the FlowiseAI bug: internal/derived/trust fields are accepted straight from client input and persisted.

### Impact Explanation
The persisted `shared_address` and `status` are later trusted by `pay()`, which sends real funds to `objContract.shared_address` once `status === "signed"`: [5](#0-4) 

If a device that is a legitimate cosigner on one of the victim's multisig ("shared") addresses sends a forged `arbiter_contract_shared` message for a *new* contract hash (one the victim has not seen before, so the `INSERT IGNORE` succeeds) with `status: "signed"` and `shared_address: <attacker address>`, the record is stored as an apparently ready-to-pay, already-signed contract. If the victim (acting as `me_is_payer`) subsequently triggers `pay()` for that contract — e.g. via wallet UI showing a "ready to pay" contract — funds are sent directly to the attacker's `shared_address` instead of a cryptographically-derived multisig address. This is concrete unauthorized fund loss, not merely metadata corruption.

### Likelihood Explanation
The trigger is reachable by a "paired device" — a cosigner already sharing a wallet's signing paths — which the rules explicitly allow as an in-scope actor. No hub/node compromise, no malicious peer assumption beyond a device the victim has already paired as a cosigner, and no special privilege beyond being a cosigner is required. The check gating the whole flow (`SELECT 1 FROM my_addresses JOIN wallet_signing_paths ... WHERE device_address=from_address`) is satisfied by design for any legitimate cosigner, so a cosigner turning malicious can exploit this without further steps.

### Recommendation
- In `store()`, always force `status` to `status_PENDING` for newly-shared contracts regardless of `bFromCosigner`, and never accept `shared_address`/`unit` from `arbiter_contract_shared` payloads without independent verification.
- Route any `shared_address` or `unit` value received from a cosigner through the same cryptographic re-derivation/verification used in `handleReceivedSharedAddress`/`handleReceivedSigningUnit` before persisting or trusting them.
- Apply an explicit whitelist of client-settable fields for every code path that persists contract data supplied by a peer or cosigner device, mirroring `setField`'s allow-list but enforcing it at `store()` time too.

### Proof of Concept
1. Attacker device `D` is a legitimate cosigner sharing signing paths on victim's address `my_address` (a normal multisig setup).
2. `D` fabricates a contract object with a fresh `hash` (never seen by the victim), consistent `title/text/creation_date/addresses/amount/asset` (so `getHash(body)` matches), but sets `status: "signed"`, `shared_address: <attacker_address>`, `unit: <arbitrary_or_omitted>`.
3. `D` sends this as an `arbiter_contract_shared` message to the victim's device.
4. Victim's `wallet.js` passes the ownership check (D is indeed a cosigner of `my_address`) and calls `arbiter_contract.store(body, true)`, inserting the record with attacker-controlled `status`/`shared_address` since these are not covered by the hash check and `store()` does not sanitize them.
5. If the victim later calls `pay(hash, ...)` for this contract (e.g., prompted by UI showing it as signed/ready), funds are sent to `<attacker_address>` instead of a legitimate multisig-derived shared address.

### Citations

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

**File:** arbiter_contract.js (L194-207)
```javascript
function getHashSrc(contract) {
	const payer_name = contract.me_is_payer ? contract.my_party_name : contract.peer_party_name;
	const payee_name = contract.me_is_payer ? contract.peer_party_name : contract.my_party_name;
	const payer_address = contract.me_is_payer ? contract.my_address : contract.peer_address;
	const payee_address = contract.me_is_payer ? contract.peer_address : contract.my_address;
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}

function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```

**File:** arbiter_contract.js (L632-657)
```javascript
function handleReceivedSharedAddress(hash, shared_address, from_cosigner, retry_count = 0) {
	console.log(`received shared address ${shared_address} for arbiter contract ${hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
				return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
			}
			const expected_shared_address = objectHash.getChash160(arrDefinition);
			if (expected_shared_address !== shared_address)
				return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
			console.log(`shared address ${expected_shared_address} matches the received one, setting it to the contract and sharing with cosigners`);
			setField(hash, "shared_address", shared_address, function (contract) {
				eventBus.emit("arbiter_contract_update", contract, "shared_address", shared_address);
			}, from_cosigner);
		});
	});
```

**File:** arbiter_contract.js (L692-709)
```javascript
function pay(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, function(objContract) {
		if (!objContract.shared_address || objContract.status !== "signed" || !objContract.me_is_payer)
			return cb("contract can't be paid");
		var opts = {
			asset: objContract.asset,
			to_address: objContract.shared_address,
			amount: objContract.amount,
			spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own'
		};
		if (arrSigningDeviceAddresses.length)
			opts.arrSigningDeviceAddresses = arrSigningDeviceAddresses;
		walletInstance.sendMultiPayment(opts, function(err, unit){								
			if (err)
				return cb(err);
			setField(objContract.hash, "status", "paid", function(objContract){
				cb(null, objContract, unit);
			});
```
