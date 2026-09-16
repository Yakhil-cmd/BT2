## Title
Ambiguous (delimiter-less) hash serialization of arbiter contracts allows hash collisions between different contract terms - (File: `arbiter_contract.js`)

### Summary
`arbiter_contract.js`'s `getHashSrc()` builds the source string that is SHA-256/base64-hashed into `contract.hash` — the identifier that both parties, cosigners, and the arbiter rely on to agree they are looking at the *same* contract. For any contract whose `creation_date` is not strictly greater than `exports.NEW_HASH_DATE` (`'2026-11-01'`), the function falls back to a legacy serialization that simply concatenates the variable-length fields with no delimiter at all: [1](#0-0) 

```js
const src = contract.creation_date > exports.NEW_HASH_DATE
     ? [...].join(exports.DELIMITER)
     : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
```

Because `contract.creation_date` is set to "now" when a contract is created (`new Date().toISOString().slice(0,19).replace('T',' ')`), and today's date (2026-09-15) is before `NEW_HASH_DATE` (2026-11-01), **every newly created arbiter contract currently uses the insecure, delimiter-less legacy path**. This is directly analogous to the vLLM `MultiModalHasher` bug: raw concatenation without unambiguous field boundaries or type/length metadata lets structurally different inputs produce identical hash outputs.

### Finding Description
`getHashSrc()`'s legacy branch joins `title`, `text`, `payer_name`, `payee_name`, `amount`, and `asset` (all variable-length strings/numbers) with `""` — no separator. Because `title` and `text` sit directly adjacent, and later `payee_name`/`amount`/`asset` are also adjacent variable-length fields, an attacker who controls the contract (`title`, `text`, `my_party_name`/`peer_party_name` via `createAndSend`) can shift the boundary between adjacent fields while producing an identical concatenated string and hence an identical `sha256` hash, e.g. `title="AB", text="C"` vs. `title="A", text="BC"`.

This is used to compute `objContract.hash` inside `createAndSend()`: [2](#0-1) 

The resulting `contract.hash` is later embedded on-chain as `"CONTRACT_" + contract.hash` inside the shared-address oscript definition that releases the escrowed funds to whichever party the arbiter names via a data feed: [3](#0-2) 

and is also checked as an integrity token in `handleReceivedSigningUnit`/`payload.contract_text_hash`: [4](#0-3) 

Since `getHashSrc` mixes `title`/`text` (attacker-controlled, free text) directly with `payer_name`/`payee_name` and even `amount`/`asset` with no separators, an offeror can craft two different sets of contract terms (e.g., different displayed title/text split, or different party name / amount split) that hash to the same `contract.hash`, hence to the same `"CONTRACT_"+hash"` oracle key used in the shared-address definition and the same `contract_text_hash` checked by the counterparty.

### Impact Explanation
Because `contract.hash` is trusted as a unique identifier of contract terms by:
- the counterparty (`payload.contract_text_hash !== contract.hash` check before treating a signing unit as valid, [5](#0-4) ),
- cosigners receiving `arbiter_contract_shared`/`arbiter_contract_update` messages,
- and the on-chain shared-address definition's `"CONTRACT_" + contract.hash` data-feed key that the arbiter uses to name a dispute winner,

a hash collision lets a malicious contract offeror present one version of contract terms to the counterparty/arbiter/cosigners for review while a colliding, differently-split variant (different title/text boundary, or different party-name/amount boundary) shares the exact same `hash`. This breaks the integrity guarantee that "same hash ⇒ same terms," enabling confusion between two different disputes/contracts referencing the same `CONTRACT_<hash>` data-feed key, or a counterparty unknowingly signing/approving text whose stored hash matches a differently-worded agreement. This can lead to disputed fund releases from the arbiter-controlled shared address (unauthorized spending / fund misdirection) and disagreement between the two devices about what was actually agreed.

### Likelihood Explanation
Reachable by any unprivileged user who initiates an arbiter contract offer (`createAndSend`) — no special privileges needed, and the vulnerable legacy code path is the *currently active* one because `NEW_HASH_DATE` (2026-11-01) has not yet passed. Constructing a colliding title/text/party-name/amount split is trivial (simple string boundary shift), so likelihood is high once an attacker chooses to exploit it, though it requires the attacker to be one of the two contracting parties.

### Recommendation
Always use the delimiter-based (or otherwise type/length-prefixed) serialization for the hash, regardless of `creation_date`, i.e., remove the legacy `join("")` branch entirely (or apply it only to genuinely historical rows being re-verified, never to newly created ones), matching the fix already implemented for the `contract.creation_date > NEW_HASH_DATE` branch using `exports.DELIMITER`. More robust: adopt the same approach as `object_hash.js`'s `getSourceString`/`getJsonSourceString`, which prefix each field with a type tag and use a control-character join char, preventing any field-boundary ambiguity.

### Proof of Concept
1. Party A creates arbiter contract #1: `title="Pay for car"`, `text="X"`, with `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset` fixed.
2. Party A (or a colluding second identity) crafts arbiter contract #2 with `title="Pay for ca"`, `text="rX"` (shifted boundary), keeping every other field byte-identical.
3. Since `creation_date` for both is "now" (before `2026-11-01`), `getHashSrc` for both contracts computes `[title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset].join("")`, which is byte-identical for #1 and #2 (`"Pay for car" + "X"` === `"Pay for ca" + "rX"`).
4. `getHash()` therefore returns the identical SHA-256/base64 value for two nominally different contracts, so `contract.hash`, the `"CONTRACT_"+hash` data-feed key in the shared-address definition, and the `contract_text_hash` integrity check are all indistinguishable between the two contracts — demonstrating the collision that undermines the integrity role `contract.hash` is meant to serve.

### Citations

**File:** arbiter_contract.js (L21-24)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
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

**File:** arbiter_contract.js (L670-676)
```javascript
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported signing unit ${unit}`);
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
```
