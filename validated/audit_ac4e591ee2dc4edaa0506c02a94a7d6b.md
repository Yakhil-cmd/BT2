## Title
Collision in `arbiter_contract.getHashSrc`/`getHash` due to unsanitized concatenation of dynamic-length fields (`title`, `text`, party names) — (File: `arbiter_contract.js`)

### Summary
`arbiter_contract.js` derives the contract's unique identifier/on-chain commitment hash (`contract_text_hash`) by concatenating multiple free-form, variable-length strings without any delimiter or length prefix, exactly the "multiple dynamic types packed together" pattern flagged in the reference report for `abi.encodePacked`. Different `(title, text, party_name, ...)` combinations can produce an identical concatenated byte string and therefore an identical SHA-256 hash, even though the actual contract content differs.

### Finding Description
`getHashSrc` builds the hash source for the (currently active, pre-`NEW_HASH_DATE`) legacy path by plain concatenation with no separator: [1](#0-0) 

Because `exports.NEW_HASH_DATE = '2026-11-01'` is in the future relative to today, every contract created "now" has `creation_date <= NEW_HASH_DATE` and therefore uses the vulnerable `.join("")` branch instead of the delimiter-protected branch: [2](#0-1) 

`title` (up to 1000 chars) and `text` (unbounded `TEXT`) are both free-form fields controlled by the contract-creating party, adjacent to each other in the concatenation with no boundary marker. An attacker can shift characters from the end of `title` into the start of `text` (or similarly between other adjacent free-text fields such as `payer_name`/`payee_name`) and produce the exact same concatenated string, hence the exact same `sha256` digest returned by `getHash`: [3](#0-2) 

This hash is not just a local database key — it is embedded as `contract_text_hash` in an on-chain `data` message that is meant to cryptographically bind the shared multisig address / signed unit to one specific contract text: [4](#0-3) 

The same hash is independently re-derived and checked in several trust boundaries reachable by an untrusted counterparty or the counterparty's device messages:
- When a cosigner receives `arbiter_contract_shared`, `wallet.js` recomputes `arbiter_contract.getHash(body)` and compares it to the attacker-supplied `body.hash`: [5](#0-4) 
- When the arbstore/arbiter receives an `arbiter_dispute_request`, it decrypts `contractContent` supplied by the disputing party and recomputes `expectedContractHash`, then checks it against the on-chain `contract_text_hash` recorded in the signed unit: [6](#0-5) 

Because collisions are trivially constructible (boundary-shifting between `title`/`text`), a malicious disputing party can present a `contractContent` (different title/text wording, e.g. altered terms) to the arbiter while `expectedContractHash` still matches the `contract_text_hash` that was actually signed on-chain by both parties for the *original* text. The arbiter has no reliable way to detect that the presented text differs from what was truly agreed, since the integrity check (hash match) passes for both variants.

### Impact Explanation
The `contract_text_hash` is the sole cryptographic guarantee that the arbiter (and later, an appeal reviewer) is judging the dispute against the actual, mutually-signed contract text. A collision lets a dishonest counterparty substitute altered legal terms (e.g., changed obligations, deadlines, or clauses embedded in `title`/`text`) that still verify against the on-chain commitment. Since arbiter resolutions directly control payout of the shared multisig funds via `CONTRACT_<hash>` data-feed messages consumed by `parseWinnerFromUnit`/`complete`, an arbiter deceived by forged contract text can be induced to award funds to the wrong party — i.e., loss of funds for the honest counterparty in the arbiter-contract payment flow. This is reachable purely from a private, attacker-controlled off-chain device message plus a normal dispute submission; no special privilege is required.

### Likelihood Explanation
Any of the two contracting parties (payer/payee), both of whom are mutually untrusted, can trigger this: they control `title`, `text`, and (for the old-format hash) `payer_name`/`payee_name` when the contract is created (`createAndSend`, `arbiter_contract.js:21-24`), and they control the `contractContent` blob decrypted at dispute time. Constructing a boundary-shift collision requires no cryptographic effort (it is a string-concatenation collision, not a hash break), only careful crafting of the two texts, making exploitation straightforward for a motivated dishonest party in an active dispute.

### Recommendation
Do not use plain concatenation for hashing dynamic-length fields. Use `object_hash.getBase64Hash`/`getSourceString`-style length/type-prefixed encoding (as already used elsewhere in `object_hash.js`/`string_utils.js`) for the source of `getHashSrc`, or explicitly hash each field separately and then hash the array of digests (Merkle-style), or retroactively enforce the already-present delimiter (`exports.DELIMITER`) unconditionally regardless of `creation_date`, rather than gating it behind a future `NEW_HASH_DATE`.

### Proof of Concept
1. Party A and Party B agree an arbiter contract with `title = "Loan Agreement"`, `text = "Amount: $500 due in 30 days"`.
2. `getHashSrc` legacy branch concatenates `title + text + creation_date + payer_name + arbiter_address + payee_name + amount + asset` with `join("")`.
3. Party A (acting in bad faith) constructs an alternate `title' = "Loan Agreement Amount: $5"`, `text' = "00 due in 30 days"` — the concatenation `title' + text'` is byte-for-byte identical to `title + text`, so `getHash` returns the identical value for both variants (all other fields unchanged).
4. When a dispute is opened, Party A sends `arbiter_dispute_request` with `encrypted_contract` containing the altered `(title', text')`; `wallet.js` recomputes `expectedContractHash` from this altered content and it matches `body.contract_hash`/`payload.contract_text_hash` from the on-chain signing unit (`wallet.js:767-807`), passing validation even though the arbiter is shown different wording than what Party B actually signed.

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

**File:** arbiter_contract.js (L205-207)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```

**File:** arbiter_contract.js (L595-604)
```javascript
					const contacts_hash = getContactsHash(contract);

					// post a unit with contract text hash and send it for signing to correspondent
					var value = {"contract_text_hash": contract.hash, "arbiter": contract.arbiter_address, contacts_hash};
					var objContractMessage = {
						app: "data",
						payload_location: "inline",
						payload_hash: objectHash.getBase64Hash(value, true),
						payload: value
					};
```

**File:** wallet.js (L659-664)
```javascript
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.peer_pairing_code || !ValidationUtils.isPositiveInteger(body.amount))
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.arbiter_address) )
					return callbacks.ifError("either peer_address or address or arbiter_address or shared_address are not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
```

**File:** wallet.js (L767-807)
```javascript
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
				const requestUnit = conf.bLight
					? (onDone) => network.requestHistoryFor([body.unit], [], err => {
						if (!err) return onDone();
						console.log("failed to load signing unit " + body.unit + " for dispute request, will try again in 30s");
						setTimeout(() => requestUnit(onDone), 30000);
					})
					: (onDone) => onDone();
				requestUnit(async () => {
					const objUnit = await storage.readUnit(body.unit);
					if (!objUnit)
						return callbacks.ifError("signing unit not found");
					const dataMessage = objUnit.messages.find(msg => msg.app === 'data');
					if (!dataMessage)
						return callbacks.ifError("no data message in signing unit");
					const { payload } = dataMessage;
					const contacts_hash = arbiter_contract.getContactsHash({
						me_is_payer: body.me_is_payer,
						my_pairing_code: body.my_pairing_code,
						peer_pairing_code: body.peer_pairing_code,
						my_contact_info: contractContent.my_contact_info,
						peer_contact_info: contractContent.peer_contact_info,
					});
					if (payload.contacts_hash !== contacts_hash)
						return callbacks.ifError("contacts hash doesn't match the signing unit");
					if (payload.contract_text_hash !== body.contract_hash)
						return callbacks.ifError("contract hash doesn't match the signing unit");
```
