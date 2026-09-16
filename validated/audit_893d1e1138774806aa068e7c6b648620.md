### Title
Full unrestricted export of internal `wallet_arbiter_contracts` row to cosigner devices via `shareContractToCosigners` - (File: arbiter_contract.js)

### Summary
`shareContractToCosigners()` broadcasts the entire local database row for an arbiter contract — fetched with `SELECT * FROM wallet_arbiter_contracts WHERE hash=?` — to every device address returned by `getAllMyCosigners()`, without filtering the row down to the fields the cosigners are actually supposed to see.

### Finding Description
`getByHash()` reads all columns of `wallet_arbiter_contracts` with an unrestricted `SELECT *`: [1](#0-0) 

`shareContractToCosigners()` then forwards this entire row object, unmodified, to every cosigner device over the paired-device messaging channel: [2](#0-1) 

This function is reachable in normal flow whenever a contract is accepted (`respond()` with `status === "accepted"`) or when a shared address is created (`createSharedAddressAndPostUnit`), both of which are triggered as part of processing an `arbiter_contract_offer`/related message that can be initiated by an untrusted peer device: [3](#0-2) [4](#0-3) 

By contrast, `shareUpdateToPeer`/`shareUpdateToCosigners` are careful to send only a single named `field`/`value` pair: [5](#0-4) 

but `shareContractToCosigners` does not apply the same restriction — it sends the complete row, including internal bookkeeping columns such as `my_pairing_code` (the device's permanent pairing secret: `device_pubkey@hub#pairing_secret`), `arbstore_address`, `arbstore_device_address`, `cosigners` (JSON list of device addresses), and other columns that were never intended to be shared verbatim with every cosigner. This mirrors the TYPO3 export bug class (GHSA-8gmv-9hwg-w89g): a data-export/sharing routine that selects/forwards an entire table row instead of restricting the output to an explicit allow-list of columns, thereby disclosing internal details to a party that only needed a subset of the data.

The `my_pairing_code` field is particularly sensitive: it is the same permanent pairing string generated via `device.getOrGeneratePermanentPairingInfo()` and is otherwise deliberately shared only with the intended contract counterparty in `respond()`. Sending it unconditionally to *all* cosigners (multiple recipients, whose device addresses are pulled from `wallet_signing_paths`/`my_addresses`) in `shareContractToCosigners` broadens the audience for a value equivalent to a long-lived pairing credential.

### Impact Explanation
Any device that is or becomes a cosigner on the wallet used for the contract's `my_address` will receive the full `wallet_arbiter_contracts` row for every contract that reaches "accepted" or "shared_address" status, including the local user's permanent pairing secret and internal arbstore endpoint bookkeeping data. This is an information-disclosure issue rather than fund loss: it does not by itself enable unauthorized spending, but it leaks credential-like data (`my_pairing_code`) and internal contract metadata to a broader set of recipients than intended, satisfying CWE-200/CWE-319 in the same manner as the TYPO3 advisory (unrestricted column export exposing internal details to authenticated-but-not-fully-privileged parties).

### Likelihood Explanation
The path is reachable purely by ordinary paired-device contract negotiation: an arbiter-contract counterparty (an untrusted paired device) sends a contract offer, and normal user acceptance (`respond` with status "accepted") or shared-address creation triggers `shareContractToCosigners` automatically, with no additional privilege required from the peer beyond being an already-paired device party to the contract. Any cosigner on the local multi-sig wallet automatically receives the full record on every such event.

### Recommendation
Restrict `shareContractToCosigners` to send only the explicit subset of fields that cosigners actually need (e.g., hash, parties, amount, asset, arbiter, status, shared_address), mirroring the field-level restriction already used in `shareUpdateToCosigners`/`shareUpdateToPeer`, and exclude internal/sensitive fields such as `my_pairing_code`, `arbstore_address`, `arbstore_device_address`, and any other bookkeeping columns from the row before transmission.

### Proof of Concept
1. Attacker (peer B) pairs with victim (peer A) and sends an `arbiter_contract_offer` to establish an arbiter contract, with peer A having at least one cosigning device on the wallet holding `my_address`.
2. Victim accepts the contract (`respond(hash, "accepted", ...)`), which calls `shareContractToCosigners(objContract.hash)`.
3. `getByHash` performs `SELECT * FROM wallet_arbiter_contracts WHERE hash=?`, returning all columns.
4. `shareContractToCosigners` sends this entire object, unfiltered, via `device.sendMessageToDevice(device_address, "arbiter_contract_shared", objContract)` to every device address in `getAllMyCosigners(hash)`.
5. Any cosigner device thereby receives `my_pairing_code` and other internal fields it was not meant to receive, which it can use to pair to the victim's device outside the intended flow.

### Citations

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

**File:** arbiter_contract.js (L118-154)
```javascript
function respond(hash, status, signedMessageBase64, signer, cb) {
	cb = cb || function(){};
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending" && objContract.status !== "accepted")
			return cb("contract is in non-applicable status");
		var send = function(authors, pairing_code) {
			var response = {hash: objContract.hash, status: status, signed_message: signedMessageBase64, my_contact_info: objContract.my_contact_info};
			if (authors) {
				response.authors = authors;
			}
			if (pairing_code) {
				response.my_pairing_code = pairing_code;
			}
			device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_response", response);

			setField(objContract.hash, "status", status, function(objContract) {
				if (status === "accepted") {
					shareContractToCosigners(objContract.hash);
				};
				cb(null, objContract);
			});
		};
		if (status === "accepted") {
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				setField(objContract.hash, "my_pairing_code", pairing_code);
				composer.composeAuthorsAndMciForAddresses(db, [objContract.my_address], signer, function(err, authors) {
					if (err) {
						return cb(err);
					}
					send(authors, pairing_code);
				});
			});
		} else {
			send();
		}
	});
```

**File:** arbiter_contract.js (L168-176)
```javascript
function shareContractToCosigners(hash) {
	getByHash(hash, function(objContract){
		getAllMyCosigners(hash, function(cosigners) {
			cosigners.forEach(function(device_address) {
				device.sendMessageToDevice(device_address, "arbiter_contract_shared", objContract);
			});
		});
	});
}
```

**File:** arbiter_contract.js (L178-192)
```javascript
function shareUpdateToCosigners(hash, field) {
	getByHash(hash, function(objContract){
		getAllMyCosigners(hash, function(cosigners) {
			cosigners.forEach(function(device_address) {
				device.sendMessageToDevice(device_address, "arbiter_contract_update", {hash: objContract.hash, field: field, value: objContract[field]});
			});
		});
	});
}

function shareUpdateToPeer(hash, field) {
	getByHash(hash, function(objContract){
		device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_update", {hash: objContract.hash, field: field, value: objContract[field]});
	});
}
```

**File:** arbiter_contract.js (L586-593)
```javascript
			ifOk: function(shared_address){
				setField(hash, "shared_address", shared_address, async function(contract) {
					const err = await fillArbstoreAddresses(contract);
					if (err)
						return cb(err);
					// share this contract to my cosigners for them to show proper ask dialog
					shareContractToCosigners(contract.hash);
					shareUpdateToPeer(contract.hash, "shared_address");
```
