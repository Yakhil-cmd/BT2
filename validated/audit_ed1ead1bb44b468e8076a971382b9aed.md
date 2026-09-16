### Title
Arbiter contract hash uses unbounded field concatenation with no delimiter, allowing forged dispute content to collide with an agreed contract hash - (File: arbiter_contract.js)

### Summary
`arbiter_contract.getHashSrc()` computes the on-chain-referenced "contract hash" by concatenating contract fields (`title`, `text`, `creation_date`, party names, `arbiter_address`, `amount`, `asset`) with a delimiter, but only for contracts whose `creation_date > exports.NEW_HASH_DATE` ('2026-11-01'). Since today's date is 2026-09-15, every contract currently created falls into the legacy branch, which joins the same fields with `""` (no delimiter at all): ` [1](#0-0) `. This is the same bug class as the GnuPG "status line injection" report: concatenating attacker-influenced fields without an unambiguous boundary lets different field-value splits hash-collide, so a party can present altered content that verifies against a hash the counterparty/arbiter already trusted.

### Finding Description
`getHashSrc` builds the string that is SHA-256-hashed into `objContract.hash`, and for the legacy (currently active) date range it is:
```
[contract.title, contract.text, contract.creation_date, payer_name, contract.arbiter_address, payee_name, contract.amount, contract.asset].join("")
```
` [2](#0-1) `

None of `title`, `text`, `payer_name`/`payee_name` (free-text party names supplied by users, see `createAndSend`/`store` inserting `my_party_name`/`peer_party_name` verbatim) are validated to be free of arbitrary byte sequences, and there is no separator between adjacent string fields. Because `String.prototype.join("")` provides no boundary, the byte sequence `title + text + creation_date + payer_name + ...` is not an injective encoding of the tuple of fields: shifting characters across the `title`/`text` boundary (or `text`/`creation_date`, or the name fields) produces an identical concatenated string and thus an identical SHA-256 hash, exactly the "ambiguous status-line/field boundary" root cause described in the GnuPG report.

This hash is the trust anchor used later to authenticate contract content that is disclosed only at dispute time:
- The dispute payload embeds `contract_text_hash`, and the on-chain signing unit's data message is checked against it: `payload.contract_text_hash !== contract.hash` in `handleReceivedSigningUnit` ` [3](#0-2) `.
- When an arbstore forwards a dispute to the arbiter, the arbiter's wallet independently recomputes the expected hash from the *encrypted, party-supplied* `contractContent` (`title`, `text`, party names, `creation_date`) and compares it to the `contract_hash` referenced on-chain, accepting the content as authentic if it matches: ` [4](#0-3) `.

Because the hash function is not collision-resistant with respect to field boundaries (it is a simple concatenation), a contract party who controls both endpoints of the negotiation (title/text at offer time, or crafted `my_party_name`) can construct two different `(title, text, party_name, ...)` tuples whose concatenation is byte-identical, producing the same `contract.hash`/`contract_text_hash` for two different actual agreements. The counterparty's device only ever validates the *hash* equality (`body.hash !== arbiter_contract.getHash(body)`, ` [5](#0-4) `), never the un-ambiguous re-derivation of the individual fields from a canonical encoding, so it cannot detect that an alternate split exists.

### Impact Explanation
An arbiter contract's `hash`/`contract_text_hash` is the only cryptographic binding between the encrypted contract text disclosed at dispute time and the amount actually locked/paid on-chain via the shared address. If a payer (or payee) crafts `title`/`text`/party-name values so that an alternate split of the same concatenation yields more favorable dispute terms (e.g., shifting digits that look like part of `text` into what is effectively parsed as `amount`-adjacent context, or fabricating a different `party_name`/`arbiter_address` boundary), the arbiter and the counterparty cannot cryptographically distinguish the genuine agreed content from the forged one at dispute-resolution time, since both hash to the same `contract.hash`. This can cause the arbiter to adjudicate and release AA/shared-address funds based on forged contract terms — a fund-loss/misdirection outcome for the private-payment counterparty, reachable purely by an unprivileged contract counterparty (no hub/node compromise required).

### Likelihood Explanation
Both parties to an arbiter contract are, by design, mutually distrusting; the negotiating counterparty already controls `title`, `text`, and their own `party_name`, so no privilege beyond being the offering/accepting party is needed. Constructing a colliding split (e.g., simply moving a trailing character/substring from `title` into the start of `text`, since there is zero separator) requires no cryptography — any two field splits of the same overall string collide by construction. The only obstacle is the switchover date `NEW_HASH_DATE = '2026-11-01'`, which is still in the future relative to today (2026-09-15) — meaning the vulnerable legacy branch is exactly the branch currently in production use.

### Recommendation
Use a length-prefixed or delimiter-safe canonical encoding for the legacy (and generally for any) contract-hash source string — e.g., reuse `object_hash.getSourceString`/`getJsonSourceString`, which explicitly reject `STRING_JOIN_CHAR` inside field values (` [6](#0-5) `) — instead of raw `join("")`/`join(DELIMITER)` over user-controlled strings. At minimum, reject/escape any field value containing the delimiter and prefix each field with its length before concatenation, and retire the ambiguous legacy branch as soon as possible rather than leaving it active past the code's own cut-off assumptions.

### Proof of Concept
1. Party A opens an arbiter contract offer with `title = "Pay"`, `text = "100 USD for goods"`, all other fields fixed.
2. Party A separately computes an alternate split with `title = "Pay1"`, `text = "00 USD for goods"` — the concatenation `title+text+creation_date+...` is byte-identical to case 1 (since there is no delimiter), so `getHash()` returns the same value for both.
3. Party A gets the counterparty to accept/sign against the hash computed from case 1's content.
4. At dispute time, Party A discloses the case-2 `contractContent` (`title="Pay1"`, `text="00 USD..."`) to the arbstore/arbiter via `arbiter_dispute_request`; `arbiter_contract.getHash(...)` on the arbiter's side recomputes the same hash from case 2's fields and matches `body.contract_hash` (`wallet.js:767-781`), so the forged content is accepted as authentic for adjudication even though it differs from what the counterparty actually agreed to.

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

**File:** arbiter_contract.js (L674-676)
```javascript
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
```

**File:** wallet.js (L625-627)
```javascript
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
```

**File:** wallet.js (L759-781)
```javascript
				try {
					var contractContent = device.decryptPackage(body.encrypted_contract);
				}
				catch (e) {
					return callbacks.ifError("failed to decrypt contract content: " + e);
				}
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

**File:** string_utils.js (L11-21)
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
```
