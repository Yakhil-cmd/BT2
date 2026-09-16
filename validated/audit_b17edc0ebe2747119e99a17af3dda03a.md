### Title
Naive field concatenation without delimiters in arbiter/prosaic contract hashing enables hash collisions between different contract terms - (File: arbiter_contract.js, prosaic_contract.js)

### Summary
`arbiter_contract.js` and `prosaic_contract.js` compute the canonical hash that commits to a private contract's terms (title, text, amount, asset, arbiter, party names) by concatenating these fields with plain string concatenation (or `join("")`) instead of using a length-prefixed or delimited encoding. This is the JS analogue of the reported `abi.encodePacked` hash-collision class: variable-length fields concatenated without unambiguous boundaries allow two semantically different contracts to produce the identical hash.

### Finding Description
In `arbiter_contract.js`, `getHashSrc()` builds the hash source differently depending on `contract.creation_date`: for dates before `exports.NEW_HASH_DATE = '2026-11-01'` it falls back to unbounded concatenation with `.join("")` (no separator at all) over `[title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset]`: [1](#0-0) 

Because `title`, `text`, `payer_name`, `payee_name` are free-form user-supplied strings and there is no delimiter or length prefix between fields in this legacy branch, an attacker who controls the contract offer (the peer party in an arbiter contract, an unprivileged actor reachable via `createAndSend`/`store`) can construct two different tuples of `(title, text, payer_name, payee_name, ...)` that concatenate to the exact same byte string, yielding the same `hash` for materially different contract terms. Since `exports.NEW_HASH_DATE` is set to `2026-11-01` and today's date is 2026-09-15, every contract created today still uses this vulnerable legacy concatenation path.

Similarly, `prosaic_contract.js`'s active `getHash()` (not the deprecated `getHashV1`) concatenates `title + text + creation_date` directly with no separator at all: [2](#0-1) 

This `hash` is not a cosmetic ID — it is used as the canonical commitment to contract content: when a signing unit arrives, both contract types verify authenticity of the counterparty's data-message payload by comparing it against the locally-derived hash. In `prosaic_contract.js`: [3](#0-2) 

and in `arbiter_contract.js`, the equivalent check additionally binds `arbiter_address` and `contacts_hash`: [4](#0-3) 

The `hash` also serves as the primary lookup key for the contract's state machine (`getByHash`, `setField`, `store`), and the contract's terms (amount, asset, payer/payee, arbiter) determine how a dispute is later resolved via the arbiter over the `shared_address` funds.

### Impact Explanation
Because the hash is the trust anchor that the counterparty's contract text is verified against, and it is derived without collision-resistant framing, a malicious counterparty can craft two distinct contract term sets (e.g. different `amount`/`asset`/`arbiter_address`/party names split differently across `title`/`text`/name fields) that hash-collide. This could be exploited to present one version of the terms to the victim during negotiation while a colliding-but-different version is what actually gets validated/stored/relied upon at signing or dispute-resolution time, resulting in the victim signing a shared address / releasing funds under terms different from what they believe they agreed to — a fund-loss/fund-freezing risk mediated through the arbiter contract's shared address and arbstore dispute flow.

### Likelihood Explanation
Exploitability requires an attacker to control one side of the arbiter/prosaic contract negotiation (a normal, unprivileged counterparty role reachable by anyone who pairs with a victim's wallet) and to construct colliding strings across `title`, `text`, and name fields, which are all attacker-supplied plaintext with no length or type prefixing in the vulnerable path. Crafting such a collision is a straightforward string-boundary shifting exercise (not a cryptographic hash collision), making this practically feasible.

### Recommendation
Replace ad-hoc string concatenation (`join("")`, `+`) in `getHashSrc()` (arbiter_contract.js) and `getHash()` (prosaic_contract.js) with an unambiguous encoding — e.g., always use the delimiter-based scheme already implemented for `contract.creation_date > exports.NEW_HASH_DATE`, or better, use `object_hash.getBase64Hash()`/`getSourceString()` (already used elsewhere in the codebase, e.g. `object_hash.js`) which type-tags and length-frames every field to avoid ambiguity. Retire the legacy no-delimiter path entirely rather than gating it behind a future date.

### Proof of Concept
1. Two contracts with fields `title="AB", text="X", ...` and `title="A", text="BX", ...` (all other fields identical) will produce the same `src` string in the pre-`NEW_HASH_DATE` branch of `getHashSrc()` because `.join("")` inserts no boundary between concatenated fields, and thus the same `hash`.
2. Similarly for `prosaic_contract.js`, `getHash({title:"AB", text:"C", creation_date:"D"})` equals `getHash({title:"A", text:"BC", creation_date:"D"})`.
3. An attacker offering a contract can leverage this to make the `contract_text_hash`/`hash` check in `handleReceivedSigningUnit` accept a payload corresponding to different underlying terms than the victim reviewed, since only the hash — not the full text — is authenticated at signing time. [5](#0-4)

### Citations

**File:** arbiter_contract.js (L17-19)
```javascript
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

**File:** arbiter_contract.js (L670-677)
```javascript
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported signing unit ${unit}`);
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
		const author = objUnit.authors.find(author => author.address === contract.shared_address);
```

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L169-175)
```javascript
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported prosaic signing unit ${unit}`);
		const { payload } = dataMessage;
		if (payload.contract_text_hash !== contract.hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported prosaic signing unit ${unit}`);
		setField(contract.hash, "unit", unit);
```
