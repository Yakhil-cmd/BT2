Based on my investigation, this is the strongest reachable analog.

### Title
Field-delimiter injection in arbiter-contract hash construction allows content spoofing between contract fields - (File: arbiter_contract.js)

### Summary
`getHashSrc()` builds the source string that is hashed to produce the arbiter-contract identifier by joining several user-controlled fields (`title`, `text`, `payer_name`, `payee_name`, etc.) with a fixed delimiter `exports.DELIMITER = "[|#|]"` [1](#0-0) . None of the joined fields (`title`, `text`, `contract.my_party_name` / `peer_party_name`) are validated to exclude the delimiter string before being concatenated [2](#0-1) . This mirrors CVE-2020-5217's root cause: user-supplied strings are concatenated with a separator that is later relied upon to be a hard boundary between semantically distinct fields, and no escaping/rejection of the separator character sequence is performed.

### Finding Description
`getHash(contract)` calls `getHashSrc(contract)`, which does:
```js
[contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
``` [3](#0-2) 
and then hashes the result with SHA-256 to produce `objContract.hash` used throughout the contract lifecycle (`createAndSend`, `store`, `respond`, sharing to cosigners, etc.) [4](#0-3) [5](#0-4) .

Because `title`, `text`, `my_party_name`/`peer_party_name` are free-form strings supplied by a contract-issuing peer (a paired device counterparty, in-scope per the rules), and the delimiter `"[|#|]"` is not rejected/escaped in any of them, a malicious counterparty can craft a set of field values whose concatenation with the delimiter produces the exact same source string (and hence the same hash) as a different, legitimate-looking set of field values. For example, embedding the literal delimiter inside `title` shifts the following slots, so that the string produced from `{title: "A[|#|]B", text: "C", ...}` collides with the string produced from `{title: "A", text: "B[|#|]C", ...}` (assuming remaining fields align) — i.e., two semantically different contracts (different apparent title/text boundaries) hash to the same `objContract.hash`.

### Impact Explanation
The contract `hash` is the primary key/identity used to store, look up, and share the contract data across `wallet_arbiter_contracts`, and is propagated between the two counterparties and to cosigners as the canonical reference to "this specific contract text/terms" (`getByHash`, `store`, `respond`, `shareContractToCosigners`) [6](#0-5) [7](#0-6) . If a payer or payee (a private-payment counterparty, in scope) can construct alternate contract field content that hashes identically, they can present differing terms to different recipients/arbiters while the hash-based reference implies a single canonical, immutable set of terms — enabling repudiation or substitution of contract terms (e.g., mismatched amount/asset framing perceived as unified) without detection through the hash check, undermining the arbitration/dispute process that relies on the hash to fix the agreed terms.

### Likelihood Explanation
Exploitation only requires control over the free-text `title`/`text`/party-name fields sent by one contract party to the other via `device.sendMessageToDevice`, and crafting an ASCII sequence `"[|#|]"` inside those fields — no privileged access, no network-level attack, and no cryptographic weakness needed. This is straightforward for any peer initiating or accepting a contract, making the likelihood high once the specific field boundaries are known/reverse-engineered by an attacker.

### Recommendation
Reject or escape occurrences of `exports.DELIMITER` inside `title`, `text`, `my_party_name`/`peer_party_name` (and any other field concatenated in `getHashSrc`) before hashing — analogous to the secure_headers fix that converts unsafe delimiter characters to a safe value and/or raises a validation error, ensuring the source string cannot be ambiguously re-partitioned. Alternatively, switch to a delimiter-free, unambiguous encoding (e.g., length-prefixed fields or `getSourceString`/`getJsonSourceString`-style structured hashing already used elsewhere in the codebase, such as in `object_hash.js`) so field boundaries cannot be manipulated by field content.

### Proof of Concept
1. Party A sends a contract offer with `title = "Loan[|#|]100"`, `text = "USD"`, and other fields fixed.
2. Party A also computes and could separately claim/display a contract with `title = "Loan"`, `text = "100[|#|]USD"` (same remaining fields).
3. Both produce the identical string via `[title, text, creation_date, payer_address, payer_name, arbiter_address, payee_address, payee_name, amount, asset].join("[|#|]")` in `getHashSrc()` [8](#0-7) , hence identical `objContract.hash` from `getHash()` [9](#0-8) .
4. The arbiter or counterparty relying on `hash` as the unique fingerprint of "the agreed contract text" cannot distinguish which of the two term-sets was actually agreed, since both validate against the same stored/shared hash.

### Citations

**File:** arbiter_contract.js (L17-19)
```javascript
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L21-24)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
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

**File:** arbiter_contract.js (L205-207)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```
