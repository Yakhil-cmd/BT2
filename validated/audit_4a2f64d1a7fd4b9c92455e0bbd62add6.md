### Title
Delimiter/Field-Boundary Injection in Arbiter Contract Hashing Allows Contract Content Spoofing - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js`'s `getHashSrc()` builds the cryptographic identity/integrity hash of an arbiter contract by concatenating attacker-controlled free-text fields (`title`, `text`, party names) either with **no delimiter at all** (legacy path, currently active) or with a fixed, unescaped string delimiter `"[|#|]"` (future path), exactly the CWE-93 pattern from the external report: a hash/serialization built from joined fields whose separator is not escaped or forbidden inside the field values, allowing an attacker to shift field boundaries while preserving the same hash. [1](#0-0) [2](#0-1) 

### Finding Description
`getHashSrc()` computes:
```
[title, text, creation_date, payer_name||'', arbiter_address, payee_name||'', amount, asset||'null'].join("")   // legacy, active until 2026-11-01
[title, text, creation_date, payer_address, payer_name||'', arbiter_address, payee_address, payee_name||'', amount, asset||'null'].join(exports.DELIMITER)  // DELIMITER = "[|#|]"
``` [3](#0-2) 

Because `title` and `text` (and `my_party_name`/`peer_party_name`) are attacker-supplied free text and are never validated to exclude the join delimiter (or, in the legacy branch, there is no delimiter to exclude at all), a contract-offering party can craft `title`/`text` values such that the final concatenated source string — and therefore the resulting SHA-256 hash — is identical to that of a *different* structured field split. This is the same root cause as the AVideo `ICS::escape_string()` bug: a custom ad-hoc serializer joins fields with an insufficiently escaped separator, so attacker-controlled content can inject or shift field boundaries in the serialized/hashed representation.

This differs from `string_utils.js`'s `getSourceString()`, which explicitly forbids the join character `\x00` inside string values and object keys (`variable.includes(STRING_JOIN_CHAR)` checks), showing the codebase is aware this class of bug must be defended against — but `arbiter_contract.js` reimplements string-based hashing without that protection. [4](#0-3) 

This hash is trusted as an authenticity/integrity check in two unauthenticated, peer-reachable places:
1. `arbiter_contract_offer` — the hash is checked against attacker-supplied `body` before storing the contract as legitimate: [5](#0-4) 
2. `arbiter_dispute_request` — decrypted `contractContent` (title/text/party names/amount/asset) supplied by a dispute-triggering party is re-hashed and compared to `body.contract_hash` to authenticate the terms shown to the arbiter and cross-checked against the on-chain signing unit's `contract_text_hash`: [6](#0-5) 

Because the hash cannot disambiguate two different (title, text, party-name) tuples that collapse to the same concatenated byte string, a counterparty can present contract content to the arbiter during dispute resolution that differs from what was actually negotiated/displayed to the other honest party, while still passing the `expectedContractHash` equality check.

### Impact Explanation
The arbiter-contract feature secures real fund flows: a `shared_address` escrow is created and paid into based on the agreed contract terms, and disputes are resolved by an arbiter who is shown `title`/`text`/`amount`/`asset` reconstructed from data that is only authenticated via this weak hash. Field-boundary spoofing lets a dishonest counterparty manipulate the content presented during dispute adjudication (e.g., shifting characters between `title` and `text`, or between free-text fields and adjacent structured fields) without invalidating the hash check that both the peer wallet (`arbiter_contract_offer`) and the arbstore/arbiter (`arbiter_dispute_request`) rely on to trust the content. This can bias arbitration outcomes and the resulting release of escrowed funds — a fund-loss risk for a private-payment counterparty, matching the "private payment chains" / "payment inputs and outputs" scope.

### Likelihood Explanation
Exploitation requires only that the attacker be one of the two contract parties (payer or payee) capable of freely choosing `title`/`text`/party-name content sent in an `arbiter_contract_offer` device message — no special privilege, hub/node compromise, or cryptographic break is needed. The legacy, delimiter-less branch (`join("")`) is the currently active code path since `exports.NEW_HASH_DATE = '2026-11-01'` has not yet passed, making boundary-shifting trivial (zero separator to even need to inject).

### Recommendation
Replace the ad-hoc string concatenation in `getHashSrc()` with a length-prefixed or otherwise unambiguous encoding for each field (e.g., reuse `string_utils.getSourceString()`/`getJsonSourceString()`, which already forbid the join character inside values), so that no combination of attacker-controlled field values can produce the same source string as a different field-value assignment. Reject or escape occurrences of `exports.DELIMITER` inside `title`, `text`, and party-name fields as defense in depth, and retire the legacy delimiter-less hashing path.

### Proof of Concept
Using the exposed `getHash`/`getHashSrc` (legacy branch, active today since current date < `NEW_HASH_DATE`):
```js
const arbiter_contract = require('./arbiter_contract.js');

const base = {
  title: "AB", text: "CD", creation_date: "2026-01-01 00:00:00",
  me_is_payer: true, my_party_name: null, peer_party_name: null,
  arbiter_address: "ARBITERADDR...", amount: 100, asset: null,
  my_address: "PAYERADDR...", peer_address: "PAYEEADDR..."
};
const forged = { ...base, title: "A", text: "BCD" }; // same concatenation "ABCD..."

console.log(arbiter_contract.getHash(base) === arbiter_contract.getHash(forged)); // true — hash collision despite different title/text
```
Both objects produce the identical `getHashSrc()` output `"ABCD" + creation_date + ...` and therefore the identical SHA-256 hash, even though the structured `title`/`text` split shown to the two ends differs — demonstrating that the hash used to authenticate `arbiter_contract_offer` bodies and `arbiter_dispute_request` contract content cannot detect this forged re-splitting.

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
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

**File:** string_utils.js (L17-21)
```javascript
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
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

**File:** wallet.js (L765-781)
```javascript
				if (!contractContent || !contractContent.creation_date || !contractContent.title || !contractContent.text)
					return callbacks.ifError("wrong contract content");
				var expectedContractHash = arbiter_contract.getHash({
					title: contractContent.title,
					text: contractContent.text,
					my_address: body.my_address,
					peer_address: body.peer_address,
					creation_date: contractContent.creation_date,
					my_party_name: contractContent.plaintiff_party_name,
					peer_party_name: contractContent.respondent_party_name,
					me_is_payer: body.me_is_payer,
					arbiter_address: body.arbiter_address,
					amount: body.amount,
					asset: body.asset
				});
				if (body.contract_hash !== expectedContractHash)
					return callbacks.ifError("wrong contract hash");
```
