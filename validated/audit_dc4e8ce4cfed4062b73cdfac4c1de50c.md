## Finding

Both `arbiter_contract.js` and `prosaic_contract.js` compute a commitment hash for a legally-binding contract by **concatenating free-text fields with no delimiter (or with an empty delimiter)**, meaning the hash does not uniquely bind to the displayed `title`/`text` content. This mirrors the DocuSeal bug class (displayed content ≠ canonically-committed content): the hash a device/arbiter trusts as "the contract" can be satisfied by more than one distinct `(title, text, party_name...)` combination.

Critically, `exports.NEW_HASH_DATE = '2026-11-01'` [1](#0-0)  means that **today (2026-09-15) every newly created arbiter contract still uses the vulnerable old hash branch**: [2](#0-1) 

```
const src = contract.creation_date > exports.NEW_HASH_DATE
     ? [...].join(exports.DELIMITER)
     : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
```

`prosaic_contract.js` has the same unmitigated issue permanently (no delimiter, no version gate): [3](#0-2) 

### Title
Arbiter/Prosaic Contract Hash Ambiguity Allows Content Spoofing of Signed Contract Terms - (File: arbiter_contract.js)

### Summary
`arbiter_contract.getHashSrc()` builds the hash preimage for a contract by string-concatenating `title`, `text`, `creation_date`, `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset` with **no separator** between adjacent free-text fields when `creation_date <= NEW_HASH_DATE` (`'2026-11-01'`, i.e. every contract created today) [2](#0-1) . `prosaic_contract.getHash()` has the identical flaw unconditionally, joining `title + text + creation_date` with no delimiter at all [3](#0-2) . Because there is no length-prefixing or delimiter, distinct `(title, text)` pairs can produce an identical hash simply by moving characters across the title/text boundary (e.g. `title="Pay 100", text="0 GB"` vs `title="Pay 10", text="00 GB"`).

### Finding Description
The contract `hash` is the sole cryptographic anchor that ties together:
- what is displayed/confirmed to the user in the wallet UI when a `prosaic_contract_offer` / `arbiter_contract_offer` is received [4](#0-3) ,
- what is later checked when a dispute request references it in the on-chain "data" message (`payload.contract_text_hash`) [5](#0-4) ,
- and what the arbiter is expected to read when resolving a dispute.

Since the hash preimage has no delimiter, an attacker who controls the `title`/`text` (and `party_name`) fields can construct multiple different (title, text) pairs that hash to the same value. This breaks the implicit assumption enforced throughout the code — e.g. `if (body.hash !== prosaic_contract.getHash(body))` [6](#0-5)  and `if (body.contract_hash !== expectedContractHash)` [7](#0-6)  — that a matching hash guarantees identical contract text. A malicious contract counterparty can send one `(title, text)` split to the peer for display/confirmation and later use another split with an identical hash when interacting with the arbiter/arbstore during a dispute (`arbiter_dispute_request`, decrypted via `device.decryptPackage`) [8](#0-7) , presenting different terms while all hash-equality checks still pass.

### Impact Explanation
The `wallet_arbiter_contracts` mechanism governs a shared address funded with the disputed `amount`/`asset` plus a service fee, and the arbiter's decision (driven by the contract's `title`/`text` terms it is shown) determines whether funds flow to the payer or payee. Since the hash does not uniquely commit to the contract text, this allows a dishonest peer to manipulate what content is treated as canonical at dispute time without invalidating any of the hash checks in `wallet.js`, potentially leading the arbiter to release/withhold funds based on spoofed terms — a concrete unauthorized-spending / fund-loss scenario for the honest party.

### Likelihood Explanation
Because `NEW_HASH_DATE` is set in the future (`2026-11-01`), the vulnerable, delimiter-less hashing is the **default, currently active** code path for every contract created right now, not legacy-only code. No special privileges are needed — any unit poster / contract counterparty can freely choose `title` and `text` content to engineer a collision, and the check sites (`wallet.js` lines 465-469, 780-781) rely purely on this weak hash.

### Recommendation
Use a length-prefixed or delimiter-based canonical encoding for all contract hash inputs immediately, not gated behind a future date. `prosaic_contract.js`'s `getHash` should adopt the same delimiter approach used in `arbiter_contract.js`'s new format (`exports.DELIMITER = "[|#|]"`), and `NEW_HASH_DATE` should be set to a date in the past (or the field-order/delimiter approach should be applied unconditionally) so the safe hashing scheme is actually in effect.

### Proof of Concept
1. Craft two contract objects with the same `creation_date`, `payer_address`, `arbiter_address`, `payee_address`, `amount`, `asset`, and same combined length across `title+text`, but different splits, e.g.:
   - A: `title="Pay 100"`, `text="0 GB to Alice"`
   - B: `title="Pay 10"`, `text="00 GB to Alice"`
2. Compute `getHashSrc`/`getHash` for both — they can be made identical by aligning the shift point in the free-text fields (`join("")` with no delimiter).
3. Send contract A to the peer for display/approval (`prosaic_contract_offer`/`arbiter_contract_offer`); the peer's wallet approves based on the hash matching `getHash(body)` [6](#0-5) .
4. Later, present contract B (with the same hash) to the arbiter/arbstore during dispute resolution (`arbiter_dispute_request` decrypted content) — the hash check in `wallet.js` (`payload.contract_text_hash !== body.contract_hash`) still passes [5](#0-4) , letting the dispute proceed on divergent terms.

### Citations

**File:** arbiter_contract.js (L18-19)
```javascript
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

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** wallet.js (L455-469)
```javascript
			case 'prosaic_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!(body.ttl > 0))
					return callbacks.ifError("ttl must be a positive number");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address))
					return callbacks.ifError("either peer_address or address is not valid in contract");
				if (body.hash !== prosaic_contract.getHash(body)) {
					if (body.hash === prosaic_contract.getHashV1(body))
						return callbacks.ifError("received prosaic contract offer with V1 hash");	
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

**File:** wallet.js (L793-807)
```javascript
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
