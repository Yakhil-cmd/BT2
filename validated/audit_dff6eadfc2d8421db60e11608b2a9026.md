### Title
Arbiter contract hash uses unseparated field concatenation, allowing hash collisions between different contract terms - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js`'s `getHashSrc()`/`getHash()` build the commitment hash for an arbiter contract by concatenating free-form, attacker/peer-controlled string fields (`title`, `text`, party names, `amount`, `asset`, `arbiter_address`, addresses) with **no delimiter at all** for any contract created before `exports.NEW_HASH_DATE = '2026-11-01'`. Since today's date is 2026-09-15, every contract created right now uses the no-delimiter path. This is structurally the same root cause as the reported HTTP header-injection bug (CWE-444, "Inconsistent Interpretation of ..."): unvalidated, attacker-influenced string data is concatenated into a structure that other parties parse/trust as unambiguous, when in fact field boundaries can be shifted without changing the resulting bytes, letting an attacker manufacture two semantically different messages that hash identically.

### Finding Description [1](#0-0) 
defines `DELIMITER = "[|#|]"` and `NEW_HASH_DATE = '2026-11-01'`. [2](#0-1) 
shows `getHashSrc()`:
```js
const src = contract.creation_date > exports.NEW_HASH_DATE
     ? [...].join(exports.DELIMITER)
     : [...].join("");
```
For any contract whose `creation_date` is not after `2026-11-01` (i.e., essentially all contracts today), the various string fields (`title`, `text`, `payer_name`, `payee_name`, etc.) are concatenated with **empty string** as the joiner. Because there is no unique, reserved separator between fields, two different field-value tuples can produce byte-identical concatenations (e.g. `title="AB", text="C"` vs `title="A", text="BC"` both yield `"ABC"`), and therefore identical SHA-256 hashes — a genuine, cheaply-constructible collision that requires no cryptographic break, only careful choice of adjacent free-text fields (`title`/`text` are fully attacker-controlled, per `createAndSend`/`store`, which are invoked from a "paired device" sending an `arbiter_contract_offer`/`arbiter_contract_shared` device message, see [3](#0-2)  and [4](#0-3) ).

The resulting `contract.hash` is then used as a security-relevant identifier embedded directly into the on-chain shared-address definition and the arbiter's resolution data feed key: [5](#0-4)  builds
```js
["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
```
and the arbiter posts the winner keyed only by `"CONTRACT_" + hash` (`parseWinnerFromUnit`, [6](#0-5) ). The address definition's data-feed condition checks only the hash string, not any other contract attribute, so if two different contracts (potentially with different parties/amounts, provided the differing bytes are confined to the unseparated free-text fields, or crafted so shifted bytes still coincide with the fixed-format fields) collide on `contract.hash`, an arbitration resolution intended for one dispute can satisfy the data-feed condition of a different, unrelated shared address that shares the same hash.

### Impact Explanation
This maps to "node disagreement on validity/stability" and "AA/contract fund loss" categories: a resolution posted by an arbiter for contract A could be replayed to release funds from an entirely different shared address (contract B) whose definition references the same colliding `CONTRACT_<hash>` data-feed key, because the on-chain condition is purely string-based and does not re-derive/verify the full contract content. This enables unauthorized release of escrowed funds without going through the intended dispute/arbitration process for that specific contract, i.e., a form of fund misdirection/theft within the arbiter-contract feature.

### Likelihood Explanation
Medium: exploitation requires the attacker (as one contracting party, a "paired device" reachable by any peer) to author both a legitimate-looking contract and a second, colliding contract sharing the same `arbiter_address`/hash, and to get a counterparty to sign and fund the colliding shared address before or around the time an unrelated dispute involving the same hash is resolved. This requires some setup, but no cryptographic breakage — only careful placement of attacker-controlled free-text (`title`/`text`) so the concatenated byte stream matches an existing/target contract's concatenation. The pre-`NEW_HASH_DATE` no-delimiter branch is guaranteed to be in effect today (2026-09-15 < 2026-11-01), so the bug is live in the current build.

### Recommendation
Immediately use the delimiter-based hash construction (`DELIMITER`) unconditionally rather than gating it behind `NEW_HASH_DATE`, or otherwise ensure each field is length-prefixed / unambiguously escaped before concatenation (similar to `string_utils.getSourceString`, which already null-byte-separates and rejects embedded separator bytes). Additionally, do not key on-chain arbitration outcomes solely on a peer-supplied contract hash without binding it to the full immutable contract content on-chain (or otherwise making field-boundary shifting cryptographically infeasible).

### Proof of Concept
Not fully verified end-to-end (I was unable to trace, within the available tool budget, exactly how `wallet.js`'s `arbiter_contract_offer`/`arbiter_contract_shared` handlers validate/re-derive the received hash before calling `arbiter_contract.store()`, so I cannot confirm whether an independent hash re-check on the receiving side would block a forged offer). Conceptually:
1. Attacker crafts Contract A: `title="AB"`, `text="C..."`, fixed `arbiter_address`, `amount`, `asset`, party names.
2. Attacker crafts Contract B: `title="A"`, `text="BC..."`, identical remaining fields.
3. `getHashSrc()` for both (no-delimiter branch) concatenates to the same byte string ⇒ identical SHA-256 hash.
4. Attacker gets a victim to sign/fund the shared address for Contract B (with the malicious amount/beneficiary layout attacker wants).
5. When the arbiter (or attacker acting through the arbiter's normal flow for Contract A) posts `CONTRACT_<hash>=winner` in a data feed to resolve Contract A, that data-feed entry also satisfies Contract B's shared-address definition (same hash), releasing Contract B's funds according to the winner value, independent of Contract B's actual dispute status.

Given the uncertainty about client-side hash re-validation on receipt of the offer, this should be verified in a live session before treating it as fully proven; the root-cause defect (missing delimiter in `getHashSrc` for the currently-active date branch) is confirmed directly from the source.

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

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

**File:** arbiter_contract.js (L465-480)
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
```

**File:** arbiter_contract.js (L798-814)
```javascript
function parseWinnerFromUnit(contract, objUnit) {
	if (objUnit.authors[0].address !== contract.arbiter_address) {
		return;
	}
	var key = "CONTRACT_" + contract.hash;
	var winner;
	objUnit.messages.forEach(function(message){
		if (message.app !== "data_feed" || !message.payload || !message.payload[key]) {
			return;
		}
		winner = message.payload[key];
	});
	if (!winner || (winner !== contract.my_address && winner !== contract.peer_address)) {
		return;
	}
	return winner;
}
```
