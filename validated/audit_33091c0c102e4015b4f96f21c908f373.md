### Title
Contract Hash Boundary-Confusion via Unsanitized Field Concatenation in Arbiter/Prosaic Contracts - (File: `arbiter_contract.js`, `prosaic_contract.js`)

### Summary
`arbiter_contract.js` and `prosaic_contract.js` compute the integrity hash of a peer-negotiated contract by concatenating attacker-influenceable string fields (`title`, `text`, party names, etc.) without ensuring those fields cannot themselves contain the separator (or any separator at all). This is the same root-cause class as the h3 SSE bug: values that are supposed to be delimited structural fields are interpolated into a serialized format without checking that the values don't contain the delimiter, so different logical inputs can produce the same serialized/hashed output (field-boundary confusion / injection).

### Finding Description
`prosaic_contract.js` builds the contract hash with plain string concatenation and no separator at all: [1](#0-0) 

Because there is no delimiter, `title="AB", text="CD"` and `title="A", text="BCD"` (same `creation_date`) hash-collide trivially — any redistribution of characters between `title` and `text` that preserves the concatenation produces an identical hash.

`arbiter_contract.js` was later patched to insert a delimiter (`DELIMITER = "[|#|]"`) between fields to reduce this ambiguity for contracts created after `NEW_HASH_DATE`: [2](#0-1) 

However, none of the joined fields (`title`, `text`, `payer_name`, `payee_name`, etc., which are all attacker/peer-supplied free-text values sent over `device.sendMessageToDevice`) are validated to reject occurrences of the delimiter string `"[|#|]"` itself. A counterparty can embed the literal delimiter sequence inside `title` or `text`, re-splitting the effective field boundaries used to compute the hash, so two different logical contracts (different title/text/party-name splits) can be crafted to produce the same `getHash()` value — the same "field injection via missing separator sanitization" pattern as the SSE advisory (`formatEventStreamMessage` interpolating unescaped `\n`-containing values into a newline-delimited format).

This is distinct from, and less protected than, the equivalent data-feed logic elsewhere in the codebase, where feed names/values ARE explicitly checked for the `\n` delimiter before being used in a similarly delimited format: [3](#0-2) [4](#0-3) 
No analogous check exists for `arbiter_contract.js`'s `DELIMITER` or for `prosaic_contract.js`'s unseparated concatenation.

The resulting hash (`objContract.hash` / `contract.hash`) is treated as an immutable, on-chain-anchored commitment to the contract text: when a contract is executed, a `data` message with `contract_text_hash` is put on-chain and matched against the locally stored contract: [5](#0-4) 

### Impact Explanation
Because the hash function does not injectively bind `(title, text, ...)` to its output, a malicious counterparty (a paired device — an in-scope unprivileged actor in this system) who negotiates an arbiter or prosaic contract can craft a `title`/`text` pair that renders to a favorable or fraudulent obligation while colliding with the hash that both parties/arbiter believe corresponds to an originally agreed, innocuous text. Since the arbiter's fund-release decision for a disputed shared/multisig address is driven by comparing the presented contract text against the on-chain-anchored `contract_text_hash`, this ambiguity lets an attacker present a different contract body that still validates against the same committed hash, undermining the non-repudiation guarantee the hash is meant to provide and enabling the attacker to bias arbitration outcomes that authorize release of escrowed funds — i.e., unauthorized spending from the shared address that the contract secures.

### Likelihood Explanation
Both `title` and `text` (and party names in the arbiter case) are free-form strings fully controlled by the remote peer during contract negotiation over the device-messaging channel; no length restriction, character-set restriction, or delimiter-exclusion check is applied before they are concatenated for hashing. Crafting a colliding pair requires no cryptographic effort — only choosing where to place the delimiter string or, in `prosaic_contract.js`, redistributing characters across the unseparated fields. This makes exploitation straightforward for any dishonest contract counterparty.

### Recommendation
- In both `prosaic_contract.js` and `arbiter_contract.js`, reject (or escape) occurrences of the delimiter within `title`, `text`, and party-name fields before hashing, mirroring the `indexOf('\n') >= 0` checks already used for data-feed names/values.
- Prefer a length-prefixed or structurally unambiguous encoding (e.g. `string_utils.getSourceString`, which already guards against embedded join characters) instead of raw string concatenation with a bare separator, so that field boundaries cannot be forged by the value itself.

### Proof of Concept
1. Party A proposes a prosaic contract to Party B with `title = "Pay"`, `text = " 100 to Alice"`, `creation_date = D`.
   `hash = sha256("Pay" + " 100 to Alice" + D)`.
2. A malicious Party B instead stores/presents `title = "Pay "`, `text = "100 to Alice"` (same concatenation, same `D`) — `getHash()` produces an identical value, but a downstream verifier reading fields independently (e.g., a UI or arbiter tool splitting by expected field semantics) may interpret the obligation differently while the on-chain `contract_text_hash` matches either interpretation.
3. For `arbiter_contract.js`, Party B crafts `title = "Pay[|#|]100 to Bob[|#|]"` such that splitting by `DELIMITER` re-parses into different logical `(title, text, amount recipient)` fields while still producing the same `getHashSrc()`/`getHash()` as the originally agreed contract, since no field is checked for containing the literal `"[|#|]"` sequence.

### Citations

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L167-176)
```javascript
		console.log(`signing tx ${unit} found in db, setting contract's unit`);
		const objUnit = await storage.readUnit(unit);
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported prosaic signing unit ${unit}`);
		const { payload } = dataMessage;
		if (payload.contract_text_hash !== contract.hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported prosaic signing unit ${unit}`);
		setField(contract.hash, "unit", unit);
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

**File:** validation.js (L1933-1943)
```javascript
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
```

**File:** aa_validation.js (L95-111)
```javascript
					for (var feed_name in payload) {
						var feed_name_formula = getFormula(feed_name);
						if (feed_name_formula === null) {
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
						var value = payload[feed_name];
						if (typeof value === 'string') {
							var value_formula = getFormula(value);
							if (value_formula === null) {
								if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
									return cb2("value " + value + " too long");
								if (value.indexOf('\n') >= 0)
									return cb2("value " + value + " of feed name " + feed_name + " contains \\n");
							}
```
