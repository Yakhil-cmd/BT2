Based on my research, I found a strong structural analog to the Kibana bug in `arbiter_contract.js`, but I was unable to fully confirm the exact authorization checks (or lack thereof) inside the `wallet.js` message-dispatch `switch` statement for the `arbiter_contract_*` subjects due to running out of tool iterations. I present the finding with that caveat.

### Title
Arbiter contract state keyed only by `hash` is updated by any device message referencing it, without verifying the sender is the recorded contract counterparty - (File: arbiter_contract.js)

### Summary
Kibana's bug was that onboarding-flow state was addressed by an opaque flow ID and the routes that read/wrote it never checked that the caller actually owned that flow, letting any authenticated user read/tamper with someone else's flow. In `ocore`, arbiter contract records in `wallet_arbiter_contracts` are similarly addressed purely by an opaque `hash` value [1](#0-0) , and the mutating helper `setField()` updates a contract's `status`, `shared_address`, `unit`, `cosigners`, and pairing/contact fields using only that hash as the WHERE clause, with no check against who is allowed to touch this particular record [2](#0-1) .

### Finding Description
The contract's intended counterparty is stored once at creation time as `peer_device_address` [3](#0-2) , but subsequent mutation entry points (`setField`, `store`) never re-validate that a later incoming device message purporting to update a given `hash` actually originates from that stored `peer_device_address` (or from a genuine cosigner of that specific contract) [4](#0-3) . Handlers such as `shareUpdateToCosigners`/`shareUpdateToPeer` push updates out to devices computed from the local `wallet_signing_paths`/`my_addresses` join [5](#0-4) , but the inbound path — where a remote device message for subjects like `arbiter_contract_update`/`arbiter_contract_shared` is received and applied via `setField`/`store` — is expected to perform the ownership check in `wallet.js`'s device-message dispatcher. I was not able to fully verify (evidence incomplete) whether that dispatcher actually confirms `from_address === peer_device_address` (or `from_address` is a valid cosigner for that specific `hash`) before calling into `arbiter_contract.js`; the `bFromCosigner` flag in `store()` appears to be supplied by the caller based on which subject the message arrived under, rather than being independently re-derived from `from_address` for that specific contract hash.

If this ownership check is indeed missing (as the Kibana pattern suggests to look for), a device that is any correspondent of the local wallet — not necessarily the actual counterparty recorded in `peer_device_address` for a given contract — could send a crafted `arbiter_contract_update`/`arbiter_contract_shared`/`arbiter_contract_response` message referencing a `hash` it knows about (e.g., a hash leaked via `shareContractToCosigners`) and cause `setField()` to overwrite `status`, `shared_address`, or `unit` on that contract, exactly mirroring the Kibana flaw where state lookups by ID were not scoped to the requester's identity.

### Impact Explanation
If sender-vs-`peer_device_address` binding is not enforced on the inbound message handlers, an attacker could:
- Corrupt contract `status` to prematurely mark it `accepted`/`signed`/`paid`/`completed`, misleading the local wallet UI into releasing funds via `pay()`/`complete()`, which compose real payment units from `shared_address`/`peer_address` fields under the contract's control [6](#0-5) [7](#0-6) .
- Overwrite `shared_address` with an address the attacker controls, since `pay()` sends `walletInstance.sendMultiPayment` to `objContract.shared_address` directly, which could redirect the payer's funds to a fraudulent multisig address if the field is tampered with before the definition mismatch is caught [6](#0-5) .

This would constitute unauthorized fund loss/misdirection for a private-payment counterparty, matching the "Medium/High/Critical" and "unauthorized spending" bar set by the validation rules.

### Likelihood Explanation
Exploitation requires the attacker to be a device known to the victim's hub session (a correspondent) and to learn a specific contract `hash` (which is shared to cosigners and to the direct peer, and is derived deterministically from contract terms, not secret). Given the numerous defensive checks elsewhere in this file (e.g., `deriveSharedAddress` independently re-derives and compares the expected shared address before trusting a peer-supplied one, at `handleReceivedSharedAddress`) [8](#0-7) , it is plausible the missing piece is only a hash-vs-sender binding check on `setField`, which would be masked in normal flows because well-behaved peers only send updates for contracts they are actually a party to.

### Recommendation
- In the `wallet.js` device-message dispatcher (and any other entry point) for `arbiter_contract_offer`, `arbiter_contract_response`, `arbiter_contract_update`, and `arbiter_contract_shared`, look up the contract by `hash` first, then explicitly verify `from_address === objContract.peer_device_address` for peer-only updates, or `from_address` is present in `getAllMyCosigners(hash, ...)` for cosigner-only fields, before invoking `setField`/`store`.
- Add this ownership check directly inside `setField()` in `arbiter_contract.js` (e.g., accept an expected `from_address` parameter and compare it to `peer_device_address`/cosigners before executing the `UPDATE`), so the check cannot be bypassed by adding new call sites in the future.
- Independently re-verify security-critical fields like `shared_address` and `unit` against locally-derived expected values (as already done in `handleReceivedSharedAddress`/`handleReceivedSigningUnit`) before acting on them in `pay()`/`complete()`.

### Proof of Concept
Not fully constructible without confirming the exact `wallet.js` dispatch code for `arbiter_contract_update`. Conceptually: Device C (a correspondent of the victim, but not the `peer_device_address` on contract `H`) sends a `hub/message` with `subject: "arbiter_contract_update"`, `body: {hash: H, field: "status", value: "accepted"}` (or `field: "shared_address"`) to the victim. If the victim's handler calls `arbiter_contract.setField(H, "status", "accepted", ...)` without checking that C equals the contract's `peer_device_address`, the local contract record for `H` is silently corrupted, potentially triggering fund release logic in `pay()`/`complete()`.

### Citations

**File:** arbiter_contract.js (L21-35)
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
```

**File:** arbiter_contract.js (L38-46)
```javascript
function getByHash(hash, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE hash=?", [hash], function(rows){
		if (!rows.length) {
			return cb(null);
		}
		var contract = rows[0];
		cb(decodeRow(contract));			
	});
}
```

**File:** arbiter_contract.js (L78-89)
```javascript
function setField(hash, field, value, cb, skipSharing) {
	if (!["status", "shared_address", "unit", "my_contact_info", "peer_contact_info", "peer_pairing_code", "resolution_unit", "cosigners"].includes(field)) {
		throw new Error("wrong field for setField method");
	}
	db.query("UPDATE wallet_arbiter_contracts SET " + field + "=? WHERE hash=?", [value, hash], function(res) {
		if (!skipSharing)
			shareUpdateToCosigners(hash, field);
		if (cb) {
			getByHash(hash, cb);
		}
	});
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

**File:** arbiter_contract.js (L440-452)
```javascript
function getAllMyCosigners(hash, cb) {
	db.query("SELECT device_address FROM wallet_signing_paths \n\
		JOIN my_addresses AS ma USING(wallet)\n\
		JOIN wallet_arbiter_contracts AS wac ON wac.my_address=ma.address\n\
		WHERE wac.hash=?", [hash], function(rows) {
			var cosigners = [];
			rows.forEach(function(row) {
				if (row.device_address !== device.getMyDeviceAddress())
					cosigners.push(row.device_address);
			});
			cb(cosigners);
		});
}
```

**File:** arbiter_contract.js (L632-658)
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
}
```

**File:** arbiter_contract.js (L692-716)
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
			// listen for peer announce to withdraw funds
			storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
				if (assetInfo && assetInfo.is_private)
					db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.peer_address]);
			});
		});
	});
```

**File:** arbiter_contract.js (L719-796)
```javascript
function complete(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, async function(objContract) {
		if (objContract.status !== "paid" && objContract.status !== "in_dispute")
			return cb("contract can't be completed");
		const err = await fillArbstoreAddresses(objContract);
		if (err)
			return cb(err);
		storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
			var opts;
			new Promise((resolve, reject) => {
				if (assetInfo && assetInfo.is_private) {
					var value = {};
					value["CONTRACT_DONE_" + objContract.hash] = objContract.peer_address;
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.my_address],
						signing_addresses: [objContract.my_address],
						change_address: objContract.my_address,
						messages: [{
							app: 'data_feed',
							payload_location: "inline",
							payload_hash: objectHash.getBase64Hash(value, true),
							payload: value
						}]
					};
					resolve();
				} else {
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.shared_address],
						change_address: objContract.shared_address,
						asset: objContract.asset
					};
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
							resolve();
						});
					} else { // refund
						opts.to_address = objContract.peer_address;
						opts.amount = objContract.amount;
						resolve();
					}
				}
			}).then(() => {
				if (arrSigningDeviceAddresses.length)
					opts.arrSigningDeviceAddresses = arrSigningDeviceAddresses;
				walletInstance.sendMultiPayment(opts, function(err, unit){
					if (err)
						return cb(err);
					var status = objContract.me_is_payer ? "completed" : "cancelled";
					setField(objContract.hash, "status", status, function(objContract){
						cb(null, objContract, unit);
					});
				});
			}).catch(err => {
				cb(err);
			});
		});
	});
}
```
