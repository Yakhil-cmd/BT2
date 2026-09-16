## Analysis: Analogous "identical counterparties" bug in `arbiter_contract.js`

The Sherlock report describes a class of bug where a protocol combines two addresses that are assumed to always be distinct counterparties (bull vs. bear) into shared logic/authorization without ever checking `bull != bear`. The same bug class is reachable in ocore's arbiter-contract feature, where a contract's `my_address` (offeror) and `peer_address` (acceptor) are combined into a 2-of-2 "mutual" shared-address definition, but nothing enforces that they are different addresses.

### Root cause
`createAndSend`/`store` persist a contract record built from `objContract.my_address` and `objContract.peer_address` with no equality check between them [1](#0-0) . Later, `deriveSharedAddress` builds the 2-party shared-address `arrDefinition` directly from these two fields:

```
const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
...
["and", [["address", offeror_address], ["address", acceptor_address]]]
``` [2](#0-1) 

The full definition is an `or` of branches, each requiring signatures from both `offeror_address` and `acceptor_address`, with per-path signer metadata assigned at `r.0.0` (offeror) and `r.0.1` (acceptor) [3](#0-2) . If `offeror_address === acceptor_address`, the `["and", [["address", X], ["address", X]]]` branch collapses to a condition satisfiable by a single address's signature, even though the shared address and downstream code treat it as requiring two independent parties.

This assumption is relied upon in `wallet.js`'s dispute-request handler, which checks "mutual signing" purely by the presence of authentifier paths `r.0.0` and `r.0.1`:
```
const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
``` [4](#0-3) 

If offeror and acceptor addresses are identical, a single signer controlling that one address can produce authentifiers under both `r.0.0` and `r.0.1` paths (since the underlying address-definition check for `["address", X]` at either path resolves to the same key), trivially satisfying the "mutually signed" check that is supposed to prove agreement between two separate, independent parties.

### Where the check is missing
I did not find any point in the arbiter-contract flow (`createAndSend`, `store`, `respond`, `deriveSharedAddress`, or the `wallet.js` message handlers for `arbiter_contract_offer`/`arbiter_contract_response`) that validates `objContract.my_address !== objContract.peer_address` before constructing the shared multisig definition. I was not able to fully trace the UI-layer contract-creation call site (outside the indexed files) to confirm whether an equality check exists purely client-side; if it does not exist server/module-side, a locally-modified wallet or a scripted client could still construct and offer/accept such a contract.

### Title
Arbiter-contract shared address collapses to single-signer control when `my_address` equals `peer_address` - (File: arbiter_contract.js)

### Summary
`deriveSharedAddress` in `arbiter_contract.js` builds a 2-of-2 mutual-signature shared address from `contract.my_address`/`contract.peer_address` without validating they differ, mirroring the "bull == bear" defect class: two addresses meant to represent independent counterparties can be made identical.

### Finding Description
The shared-address definition combines `offeror_address` and `acceptor_address` via `["and", [["address", offeror], ["address", acceptor]]]` [5](#0-4) . Neither `createAndSend` nor `store` reject a contract where `my_address === peer_address` [6](#0-5) . When equal, each `and` branch is satisfiable by one address's single signature, and the "mutual signing" check in `wallet.js` (paths `r.0.0` and `r.0.1`) can both be produced by that one address [7](#0-6) .

### Impact Explanation
This defeats the intended 2-party arbitration/escrow guarantee: a single party could construct or accept a contract that appears to be co-signed by two independent parties but is actually controlled entirely by them alone, then use the resulting shared address / dispute-request flow (which asserts "mutually signed" as proof of bilateral agreement) to move contract funds or trigger dispute logic that should require independent consent from both a payer and a payee. This is a fund-control/authorization integrity issue in the arbiter-contract escrow mechanism.

### Likelihood Explanation
Reachable by any unprivileged wallet user creating/accepting an arbiter contract offer through the normal `arbiter_contract_offer`/`arbiter_contract_response` device-message flow, since no code path checks address distinctness. It requires no privileged access, hub cooperation, or third-party compromise—one party simply needs to set `peer_address` equal to their own `my_address` (or a colluding second device they also control) when creating/accepting the contract.

### Recommendation
Add an explicit check in `createAndSend` and in the `store`/response-handling code (and ideally inside `deriveSharedAddress` as defense-in-depth) that rejects any contract where `objContract.my_address === objContract.peer_address`, before the record is persisted or the shared address / dispute flow is derived.

### Proof of Concept
1. Party A creates an arbiter contract via `createAndSend` setting `peer_address` equal to their own `my_address` (or to another address they also control), and `peer_device_address` to a second device they control.
2. `store`/`createAndSend` accept the contract with no distinctness check [6](#0-5) .
3. Party A calls `respond(hash, "accepted", ...)`, deriving the shared address via `deriveSharedAddress`, where `offeror_address === acceptor_address` [2](#0-1) .
4. Party A signs the resulting unit under both `r.0.0` and `r.0.1` authentifier paths using the single controlled address/key, satisfying `isMutuallySigned` in the dispute-request handler [7](#0-6)  despite there being no independent second party.

### Citations

**File:** arbiter_contract.js (L21-116)
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

function getByHash(hash, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE hash=?", [hash], function(rows){
		if (!rows.length) {
			return cb(null);
		}
		var contract = rows[0];
		cb(decodeRow(contract));			
	});
}
function getBySharedAddress(address, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE shared_address=?", [address], function(rows){
		if (!rows.length) {
			return cb(null);
		}
		var contract = rows[0];
		cb(decodeRow(contract));
	});
}

function getAllByStatus(status, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE status IN (?) ORDER BY creation_date DESC", [status], function(rows){
		rows.forEach(decodeRow);
		cb(rows);
	});
}

function getAllByArbiterAddress(address, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE arbiter_address IN (?) ORDER BY creation_date DESC", [address], function(rows){
		rows.forEach(decodeRow);
		cb(rows);
	});
}

function getAllByPeerAddress(address, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE peer_address IN (?) ORDER BY creation_date DESC", [address], function(rows){
		rows.forEach(decodeRow);
		cb(rows);
	});
}

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

**File:** arbiter_contract.js (L454-481)
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
```

**File:** arbiter_contract.js (L539-559)
```javascript
				var assocSignersByPath = {
					"r.0.0": {
						address: offeror_address,
						member_signing_path: "r",
						device_address: offeror_device_address
					},
					"r.0.1": {
						address: acceptor_address,
						member_signing_path: "r",
						device_address: acceptor_device_address
					},
					"r.1.0": {
						address: offeror_address,
						member_signing_path: "r",
						device_address: offeror_device_address
					},
					"r.2.0": {
						address: acceptor_address,
						member_signing_path: "r",
						device_address: acceptor_device_address
					},
```

**File:** wallet.js (L811-834)
```javascript
					const author = objUnit.authors.find(author => author.address === body.shared_address);
					if (!author)
						return callbacks.ifError("shared address author not found in signing unit");
					const signing_paths = Object.keys(author.authentifiers);
					const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
					if (!isMutuallySigned)
						return callbacks.ifError(`signing unit ${body.unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
					const definition = author.definition;
					if (!definition)
						return callbacks.ifError("no definition for shared address author in signing unit");
					let offeror_address, acceptor_address;
					try {
						const mutualPart = definition[1][0][1];
						offeror_address = mutualPart[0][1];
						acceptor_address = mutualPart[1][1];
					} catch (e) {
						return callbacks.ifError("unexpected definition structure in signing unit");
					}
					if (typeof offeror_address !== 'string' || typeof acceptor_address !== 'string')
						return callbacks.ifError("unexpected definition structure in signing unit");
					const bCorrectParties =
						offeror_address === body.my_address && acceptor_address === body.peer_address
						|| offeror_address === body.peer_address && acceptor_address === body.my_address;
					if (!bCorrectParties)
```
