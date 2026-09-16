### Title
Delimiter-less field concatenation in `getHashSrc()` allows hash collisions between different contract terms - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js`'s `getHashSrc()` builds the string that is hashed to produce a contract's `hash` by concatenating several attacker/counterparty-controlled, variable-length string fields. For contracts whose `creation_date` is not after `exports.NEW_HASH_DATE` ('2026-11-01') — which, given today's date, is **every contract created right now** — the fields are joined with `.join("")`, i.e. no delimiter at all, exactly the "two (or more) dynamic items concatenated ambiguously" pattern described in the external report for `abi.encodePacked()`.

### Finding Description
`getHashSrc()`:
```javascript
// arbiter_contract.js:194-203
function getHashSrc(contract) {
	...
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}
``` [1](#0-0) 

The "legacy" branch (`creation_date <= NEW_HASH_DATE`) concatenates `title`, `text`, `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset` with the empty string as separator. `title` and `text` are free-form, attacker-supplied strings (set by whichever party calls `createAndSend`), so a malicious counterparty can shift characters across the `title`/`text` boundary (or across `payer_name`/`payee_name`) to construct two semantically different contracts (different wording, different named parties) that hash to the identical `contract.hash`, exactly as the referenced `abi.encodePacked()` bug allows shifting bytes between two dynamic fields.

The same pattern, without any delimiter at all in any code path, exists in `prosaic_contract.js`:
```javascript
// prosaic_contract.js:98-104
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
``` [2](#0-1) 

This is the same class of bug flagged by the report (`hashEvidence()` concatenating two dynamic items with `abi.encodePacked()`), applied here to peer-to-peer contract hashing instead of Solidity evidence hashing.

### Impact Explanation
`contract.hash` is not a cosmetic identifier — it is embedded directly into the fund-release condition of the multisig shared address that escrows the trade:
```javascript
// arbiter_contract.js:474-480
["and", [
	["address", offeror_address],
	["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
]],
["and", [
	["address", acceptor_address],
	["in data feed", [[offeror_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
]]
``` [3](#0-2) 

and is what identifies/binds the contract when the corresponding funding unit is posted and verified:
```javascript
// arbiter_contract.js:673-676
const contacts_hash = getContactsHash(contract);
if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
	return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
``` [4](#0-3) 

If a malicious counterparty crafts a `title`/`text`/`payer_name`/`payee_name` combination that collides with the hash of the contract text the victim believes they agreed to, the victim's wallet will accept it as matching (`objContract.hash` check passes) even though the actual dispute text shown to an arbiter (via `openDispute()`, which forwards `title`, `text`, party names as free-form fields to the arbstore) can differ from what the counterparty originally offered and the victim confirmed. Because dispute resolution and the "who is entitled to the funds" outcome depend on the arbiter reading these fields, a forged-but-hash-colliding version can be used to mislead the dispute process and diverts escrowed funds to the attacker — i.e., unauthorized spending/fund loss for the victim counterparty, reachable purely by an unprivileged private-payment counterparty who proposes/accepts an `arbiter_contract`/`prosaic_contract`.

### Likelihood Explanation
Exploitation requires the attacker to be the peer proposing/negotiating a contract (fully within the reach of an "unprivileged... private-payment counterparty" per the allowed threat model). Practically finding a second-preimage collision that also constitutes plausible natural-language contract text is harder than a byte-for-byte engineered Solidity payload, but the structural weakness is identical to the quoted report and is not mitigated for the currently-default code path (legacy branch, active until `2026-11-01`), and is entirely unmitigated in `prosaic_contract.js`, which has no delimiter-based branch at all.

### Recommendation
- Use a fixed-format, unambiguous serialization for all `hash`/`getHashSrc`/`getHashV1` computations, e.g. length-prefix each field or always use a delimiter that is verified to never occur within any field, consistently across all code paths (not just contracts created after `NEW_HASH_DATE`).
- In `prosaic_contract.js`, replace direct `title + text + creation_date` concatenation with `objectHash.getSourceString()`/`getJsonSourceString()` style encoding (already used elsewhere in the codebase, e.g. `object_hash.js`, which prefixes types/lengths and rejects embedded join characters) instead of raw string concatenation.
- Retire `getHashV1`/legacy `getHash` entirely once safe, or validate that no field can contain characters used elsewhere as an implicit separator.

### Proof of Concept
Conceptual collision (not executed): For two contracts with `creation_date` on or before `2026-11-01`,
- Contract A: `title = "Pay $100 for goods"`, `text = "X"`
- Contract B: `title = "Pay $10"`, `text = "0 for goods)X"` (character `0` moved from `title` into `text`)

Both produce the same `getHashSrc()` output because `[title, text, ...].join("")` is order/length-ambiguous when concatenating adjacent dynamic strings, so `crypto.createHash("sha256").update(getHashSrc(contract)).digest("base64")` in `getHash()` [5](#0-4)  returns the same value for A and B, letting the counterparty later present contract B's terms to the arbiter/dispute flow while the victim's wallet still shows the hash matching contract A.

### Citations

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

**File:** arbiter_contract.js (L673-676)
```javascript
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
```

**File:** prosaic_contract.js (L98-104)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}

function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```
