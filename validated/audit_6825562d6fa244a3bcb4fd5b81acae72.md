### Title
Delimiter Injection in Arbiter Contract Hash Computation Allows Field-Boundary Confusion / Hash Collision - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` computes a SHA-256 hash over several contract fields (`title`, `text`, `creation_date`, party addresses/names, `arbiter_address`, `amount`, `asset`) by naively joining them with a fixed, unescaped delimiter string `"[|#|]"`. Because attacker-controlled fields (`title`, `text`) are never checked for the presence of this delimiter (or any other reserved characters), a malicious contract counterparty can embed the delimiter sequence inside `title`/`text` to shift the effective field boundaries of the concatenated hash source, producing a hash collision between two structurally different contracts. This mirrors the class of bug in CVE-2020-36309, where a mutation API accepted unsafe/unescaped characters that could be interpreted as protocol delimiters, breaking the intended separation between fields.

### Finding Description
`getHashSrc()` builds the string that is hashed to produce `contract.hash`: [1](#0-0) 

The delimiter is a fixed, predictable constant: [2](#0-1) 

`title` and `text` are supplied entirely by the contract *offeror* (a paired device / private counterparty), and the only validation performed by the receiving peer is that they are non-empty strings — no check rejects the delimiter substring, length is unbounded, and no escaping is performed before concatenation: [3](#0-2) 

Because `title` and `text` are placed first in the join order, an attacker can craft `title` (or `title`+`text`) to contain literal occurrences of `"[|#|]"` that reproduce the exact byte sequence of `creation_date`, `payer_address`, `payer_name`, `arbiter_address`, `payee_address`, `payee_name`, `amount`, and `asset` fields of an entirely different, victim-approved contract. The resulting SHA-256 digest — `getHash()` — will be identical even though the “real” structured fields (e.g. `arbiter_address`, `amount`) stored in `wallet_arbiter_contracts` differ from what an observer would derive by naively parsing the joined string back apart at delimiter boundaries.

This directly undermines the only integrity check tying the contract hash to its structured content, used in multiple trust-sensitive contexts:
- Peer swap/consistency check when an offer is received: `if (body.hash !== arbiter_contract.getHash(body)) ...` [4](#0-3) 
- The hash is embedded on-chain as the arbiter's dispute-resolution data-feed key (`"CONTRACT_" + contract.hash`) and used inside the auto-generated shared-address `oscript` definition that gates fund release: [5](#0-4) 
- The hash is also the primary key used for `INSERT OR IGNORE` on `wallet_arbiter_contracts`, so a crafted collision with an existing hash silently drops a differing contract record: [6](#0-5) 

### Impact Explanation
An attacker acting as the arbiter-contract offeror (a normal paired-device counterparty, no special privilege required) can produce two field-sets — one that a victim reviews/approves (e.g. via UI) and one that is actually bound into the on-chain dispute-resolution condition (`arbiter_address`, `amount`, `peer_address`) inside `deriveSharedAddress()` — sharing the identical `hash`. Since `hash` is the sole cryptographic binding between the contract's displayed terms and the terms encoded into the multisig/oscript shared-address definition used for real fund release, this can be leveraged to misdirect committed funds (different `arbiter_address` or `amount` than what was confirmed) or to desynchronize state between peer and cosigner devices (an existing hash silently ignoring a legitimately different contract). This falls within the explicitly in-scope categories of "hashing and signatures" and "private-payment counterparty" message handling.

### Likelihood Explanation
The offeror fully controls `title` and `text` when creating a contract offer (`createAndSend`) sent over the paired-device channel, and no server-side or peer-side validation strips or rejects the delimiter sequence or enforces field-boundary safety before hashing. Crafting a colliding pair of field sets is a straightforward string-construction exercise (no cryptographic primitive needs to be broken — it is a pure parsing/serialization ambiguity), making exploitation practical for any user who can initiate an arbiter contract with another wallet.

### Recommendation
Reject or escape occurrences of `exports.DELIMITER` in every field before it is included in `getHashSrc()` (particularly `title`, `text`, and party names), or switch to an unambiguous, length-prefixed / JSON-canonical serialization (similar to `string_utils.getSourceString`, which already defends against a `STRING_JOIN_CHAR` in values) before hashing contract fields.

### Proof of Concept
1. Attacker crafts `title` = `"X[|#|]Y[|#|]<victim_creation_date>[|#|]<victim_payer_address>[|#|]"` and `text` = `"[|#|]<attacker_arbiter_address>[|#|]<victim_payee_address>[|#|]"` etc., such that `[title, text, creation_date, payer_address, payer_name, arbiter_address, payee_address, payee_name, amount, asset].join(DELIMITER)` produces the same byte string as a benign contract with a different, victim-approved `arbiter_address`/`amount`.
2. `getHash()` returns the same SHA-256 digest for both structurally different contracts.
3. Attacker sends the crafted `arbiter_contract_offer` (fields set to attacker's malicious values, but with `title`/`text` containing embedded delimiter sequences making the hash equal to the benign one the victim expects/has cached), passing the `body.hash !== arbiter_contract.getHash(body)` check in `wallet.js`, and the resulting shared-address dispute condition is derived from the attacker's real (differing) `arbiter_address`/`amount` fields while the hash matches the one the victim believes corresponds to the originally agreed terms.

### Citations

**File:** arbiter_contract.js (L17-19)
```javascript
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L94-111)
```javascript
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
```

**File:** arbiter_contract.js (L194-203)
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
```

**File:** arbiter_contract.js (L474-480)
```javascript
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
```

**File:** wallet.js (L617-635)
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
```
