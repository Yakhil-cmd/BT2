### Title
Arbiter contract hash is not unique and collides on retries/duplicate terms, causing contract-creation DoS - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` derives the on-chain-independent identifier of a private arbiter contract (`objContract.hash`) purely from user/peer-controlled, repeatable fields — title, text, creation date truncated to the second, payer/payee addresses and names, arbiter address, amount and asset — with no random nonce or monotonically-increasing counter, exactly the bug class described in the reported `OrderId` issue (hash of request parameters used as a supposedly-unique identifier).

### Finding Description
`getHash()`/`getHashSrc()` compute the contract hash by hashing a delimited string of `title, text, creation_date, payer_address, payer_name, arbiter_address, payee_address, payee_name, amount, asset` (or the legacy pre-`NEW_HASH_DATE` variant), with `creation_date` populated at second granularity by `createAndSend()`. [1](#0-0) [2](#0-1) 

This `hash` is used as the primary lookup/identifier key for the contract throughout the module — `getByHash`, `setField`, `respond`, `revoke`, `shareUpdateToCosigners`/`shareUpdateToPeer` all key off it — and it is inserted directly into `wallet_arbiter_contracts` via a plain `INSERT` in `createAndSend()` (no `OR IGNORE`), while the peer-side `store()` function explicitly guards against duplicate-hash inserts with `db.getIgnore()`. [3](#0-2) [4](#0-3) [5](#0-4) 

Because none of the hashed fields is guaranteed unique per contract offer — a paired-device counterparty (or the user themself, via a UI retry after a slow/failed response) can trivially cause two distinct contract-creation attempts with identical `title`, `text`, `amount`, `asset`, `arbiter_address`, and party names within the same second — the resulting `hash` will collide.

### Impact Explanation
- On the offering side, `createAndSend()`'s bare `INSERT` will violate the uniqueness of `hash` in `wallet_arbiter_contracts` and fail, so a legitimate retry (e.g. after a lost `arbiter_contract_offer` device message) of an otherwise-independent contract with the same terms cannot be created, denying service to the user for that specific contract flow.
- On the receiving/`store()` side, the collision is silently swallowed by `INSERT OR IGNORE`, so a second, genuinely distinct contract offer with the same terms from the same peer within the same second is dropped without any error surfaced to either party — exactly the "backend can get messed up and think two [objects] are the same" consequence called out in the report, since `getByHash`/`setField`/`respond`/`revoke` will now operate on the wrong (first) contract record while the user believes they are acting on the second.
- Because `status`, `shared_address`, `unit`, and `resolution_unit` are all mutated by hash via `setField`, a collision causes one party's genuine second contract to inherit/overwrite state (e.g. `status`) belonging to an unrelated earlier contract, which can freeze or misroute the correct arbiter-contract negotiation/settlement flow for the counterparty.

### Likelihood Explanation
This requires only two device-paired counterparties negotiating an arbiter contract with identical parameters within the same one-second window — a common occurrence for retried/duplicate offers or when a peer intentionally sends the same offer twice — so it is easily reachable without any privileged access, matching the allowed "private-payment counterparty / paired device" attack surface.

### Recommendation
Include a source of uniqueness that is not attacker/user-repeatable in the hashed contract material — e.g. a random nonce, a monotonically increasing per-device counter, or the device-message hash — instead of (or in addition to) second-granularity `creation_date`, and make `createAndSend()`'s insert idempotent (`INSERT OR IGNORE`/`OR REPLACE` with explicit collision handling) rather than assuming the derived hash is unique.

### Proof of Concept
1. Device A and Device B are paired for arbiter contracts.
2. Device A calls `createAndSend()` twice within the same second with identical `title`, `text`, `my_address`, `peer_address`, `arbiter_address`, `amount`, and `asset` (e.g., a UI double-submit or automatic retry after no response), producing two `objContract` instances that hash to the same `objContract.hash` via `getHash`/`getHashSrc`. [6](#0-5) 
3. The first `INSERT INTO wallet_arbiter_contracts` succeeds; the second, identical-hash `INSERT` (no `OR IGNORE`) fails due to the unique `hash` key, so the second, independently-intended contract is never persisted or sent, and the caller only sees a raw DB error rather than a clear "duplicate" indication. [3](#0-2) 
4. Conversely, if Device B is the one whose `store()` receives two colliding `arbiter_contract_offer`/`arbiter_contract_shared` messages with the same computed hash, the second is dropped by `INSERT OR IGNORE`, and subsequent `respond()`/`revoke()`/`setField()` calls by Device B keyed on `hash` operate on the first (stale) contract instead of the intended second one. [7](#0-6) [8](#0-7)

### Citations

**File:** arbiter_contract.js (L21-27)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
	device.getOrGeneratePermanentPairingInfo(pairingInfo => {
		objContract.my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
		db.query("INSERT INTO wallet_arbiter_contracts (hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, my_contact_info, my_pairing_code, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 0, objContract.creation_date, objContract.ttl, status_PENDING, objContract.title, objContract.text, objContract.my_contact_info, objContract.my_pairing_code, JSON.stringify(objContract.cosigners) ... (truncated)
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

**File:** arbiter_contract.js (L91-115)
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
