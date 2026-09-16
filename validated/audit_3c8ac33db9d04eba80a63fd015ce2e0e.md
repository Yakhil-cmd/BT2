## Analysis [1](#0-0) 

The reference CVE's root cause is generic: **fields are concatenated with a fixed delimiter without verifying that user-controlled field values don't already contain that delimiter**, so a crafted value can be mistaken for a field boundary. `ocore`'s own `getSourceString()` shows the *correct* way to do this — it explicitly rejects any string/key containing the join character (`STRING_JOIN_CHAR = "\x00"`) before joining, precisely to prevent this class of bug: [2](#0-1) 

However, `arbiter_contract.js`'s contract-hash derivation does **not** apply this protection when it concatenates untrusted, free-form contract fields with a fixed textual delimiter: [3](#0-2) [4](#0-3) 

`contract.title`, `contract.text`, and the party names are attacker-controlled strings (set by either counterparty when proposing/accepting an arbitered contract) and are never checked for containing the literal delimiter sequence `"[|#|]"`. Because `Array.join()` is a lossy, ambiguous encoding when a field can itself contain the separator, two structurally different contracts (e.g. one with `title="A[|#|]B", text="C"` and another with `title="A", text="B[|#|]C"`, with the rest of the fields identical) collapse to the **identical joined string**, and therefore the **identical SHA-256/base64 hash** used as the wallet's `wallet_arbiter_contracts.hash` primary key and as the value shared with the peer/arbiter to identify the contract: [5](#0-4) 

The legacy `prosaic_contract.js` hashing path is even more exposed, since it concatenates fields with **no delimiter at all**: [6](#0-5) 

`getContactsHash()` in the same file has the analogous problem for pairing/contact info, joined with a single `"|"` character with no escaping: [7](#0-6) 

### Title
Hash-boundary injection in arbiter/prosaic contract hashing allows content-ambiguous hash collisions - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` (`getHashSrc`/`getHash`) and `prosaic_contract.js` (`getHashV1`) compute the identifying hash of a peer-to-peer arbitered/prosaic contract by concatenating user-supplied free-text fields (`title`, `text`, party names) with either a fixed delimiter or no delimiter at all, without verifying the fields don't already contain the separator sequence. This mirrors the CVE-2026-46740 root cause: unescaped delimiter characters in untrusted values let an attacker forge/collide the boundary-sensitive serialization.

### Finding Description
`getHashSrc()` joins ten contract fields with the constant `exports.DELIMITER = "[|#|]"`, or (for contracts predating `NEW_HASH_DATE`) simply concatenates them with no delimiter. None of `contract.title`, `contract.text`, `payer_name`, `payee_name` are validated to be free of the delimiter substring before being joined. `getContactsHash()` has the same problem with a single-character `"|"` delimiter for pairing codes/contact info. Since string concatenation with a reusable, non-length-prefixed delimiter is not a bijective encoding when the delimiter can appear inside a field, a malicious contract proposer/counterparty can choose `title`/`text`/party-name values that shift content across the intended field boundary while producing the exact same joined byte string (and therefore the exact same SHA-256/base64 hash) as a contract with substantively different terms.

### Impact Explanation
`contract.hash` is used as the unique key (`wallet_arbiter_contracts.hash`) and as the value exchanged with the peer/arbstore to reference "the agreed contract." If two semantically different contract bodies can be engineered to share a hash, a dishonest party in a private arbitered contract can present, store, or later reference conflicting contract content under one shared hash identifier, undermining the tamper-evidence property the hash is meant to provide for a payment/arbitration agreement between an unprivileged private-payment counterparty and the arbiter. This is a wallet/contract-message-handling integrity flaw reachable purely from the private-payment counterparty side, without any special privileges.

### Likelihood Explanation
Exploitation only requires crafting ordinary text fields (`title`, `text`, party name) containing the literal delimiter string `"[|#|]"` or `"|"` — both are plain ASCII sequences with no input filtering preventing their use in these free-text fields, making this trivially reachable by either contract counterparty.

### Recommendation
Adopt the same discipline already used in `string_utils.getSourceString()`: reject (or type/length-prefix) any field value containing the delimiter before joining, or switch to an unambiguous, tagged serialization (e.g., `getJsonSourceString`/`getSourceString`) for computing `arbiter_contract` and `prosaic_contract` hashes instead of raw delimiter-joined concatenation.

### Proof of Concept
1. Party A proposes an arbiter contract with `title = "Pay rent[|#|]May"`, `text = ""`, and the remaining fields fixed.
2. Party B (or a colluding actor) constructs an alternate contract with `title = "Pay rent"`, `text = "May"`, and identical remaining fields.
3. `getHashSrc()` joins the ten fields with `"[|#|]"` for both contracts; because the delimiter is embedded inside the first contract's `title`, the resulting joined strings are byte-identical, so `getHash()` produces the same hash for both semantically different contracts. [8](#0-7)

### Citations

**File:** string_utils.js (L11-29)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
```

**File:** arbiter_contract.js (L19-19)
```javascript
exports.DELIMITER = "[|#|]";
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

**File:** arbiter_contract.js (L209-216)
```javascript
function getContactsHash(contract) {
	const payer_pairing_code = contract.me_is_payer ? contract.my_pairing_code : contract.peer_pairing_code;
	const payee_pairing_code = contract.me_is_payer ? contract.peer_pairing_code : contract.my_pairing_code;
	const payer_contact_info = contract.me_is_payer ? contract.my_contact_info : contract.peer_contact_info;
	const payee_contact_info = contract.me_is_payer ? contract.peer_contact_info : contract.my_contact_info;
	const src = [payer_contact_info || '', payer_pairing_code || '', payee_contact_info || '', payee_pairing_code || ''].join("|");
	return crypto.createHash("sha256").update(src, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L102-104)
```javascript
function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```
