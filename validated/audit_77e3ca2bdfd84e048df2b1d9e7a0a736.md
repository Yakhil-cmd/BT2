### Title
Field-boundary collision in arbiter-contract text hashing via unseparated `Array.join("")` - (File: arbiter_contract.js)

### Summary
`getHashSrc()` in `arbiter_contract.js` builds the source string for the arbiter-contract's `hash` by concatenating several attacker/peer-controlled dynamic strings (`title`, `text`, `payer_name`, `payee_name`, etc.). For any contract whose `creation_date` is not strictly greater than `exports.NEW_HASH_DATE` (`'2026-11-01'`), the fields are joined with `""` (empty separator) instead of the `exports.DELIMITER` used in the "new" branch: [1](#0-0) 

Since `NEW_HASH_DATE` is set to a date in the future relative to the current date, every contract created today falls into the vulnerable unseparated branch.

### Finding Description
This is a direct analog of the reported `abi.encodePacked()` collision class: concatenating multiple variable-length strings without an unambiguous delimiter makes the resulting hash pre-image ambiguous. Here, `getHashSrc()` for "old" contracts does:

```
[contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("")
``` [2](#0-1) 

`title`, `text`, `payer_name`, and `payee_name` are all attacker/peer-supplied free-text strings with no length restriction and no embedded separator, so `title="Contract A" + text="terms X"` and `title="Contract" + text=" A terms X"` (i.e., moving characters across the field boundary) hash to the identical `sha256` digest via `getHash()`: [3](#0-2) 

The resulting `contract.hash` is treated as the canonical, collision-free identifier for the whole agreement throughout the flow:
- It is persisted as the contract's `hash` and used as the primary lookup key (`getByHash`), and it is what gets shared with the peer and cosigners in `arbiter_contract_offer`/`arbiter_contract_shared` messages.
- When the shared multisig address is created and the parties commit to signing, the contract hash is embedded on-chain in a `data` message as `contract_text_hash`, alongside `contacts_hash` and `arbiter`: [4](#0-3) 
- When a peer/cosigner receives a purportedly signed unit, the code re-derives `getContactsHash(contract)` from its *local* copy of the contract and checks only that `payload.contract_text_hash === contract.hash` — it never recomputes `getHashSrc` from the on-chain payload text, and the on-chain payload does not carry the actual `title`/`text` at all, only the hash: [5](#0-4) 

Because the on-chain commitment is only the (colliding) `hash`, a counterparty who controls the `title`/`text` fields at contract-creation time (the offeror, since `createAndSend` computes `objContract.hash = getHash(objContract)` from data they alone author) can craft two different `title`/`text` payloads that both hash to the same value: [6](#0-5) 

### Impact Explanation
This is an unprivileged, private-payment-counterparty–reachable weakness: any device that composes an arbiter contract offer controls the strings that later become the immutable on-chain proof text of that contract. Because the join has no delimiter, an attacker can present one version of the contract text to the counterparty for review/acceptance while a differently-worded version (shifting characters across field boundaries) also validates against the exact same `contract_text_hash` that ends up anchored on-chain and is used to gate mutual-signing/payout logic in `handleReceivedSigningUnit`. This undermines the non-repudiation guarantee the hash is meant to provide for a private, off-chain arbitration agreement backed by an on-chain multisig/arbiter payment — the party relying on the hash as proof of agreed terms cannot be certain which exact text (title/text boundary) it commits to. In an arbitration dispute, this ambiguity in the provable contract text can be used to argue divergent terms were "hashed", weakening the arbiter's or payer's ability to prove which text corresponds to the funds locked in the shared address.

### Likelihood Explanation
High: the vulnerable branch (`.join("")`, no delimiter) is the one currently active for all contracts, since `NEW_HASH_DATE = '2026-11-01'` is still in the future relative to today; every contract created before that date uses the collision-prone hashing path. No privileged access is required — a normal arbiter-contract offeror (an ordinary wallet user) fully controls `title` and `text` and can trivially construct two boundary-shifted payloads with identical hashes.

### Recommendation
Always join the dynamic fields in `getHashSrc()` with an unambiguous delimiter that cannot appear inside the individual fields (as already done in the "new" branch via `exports.DELIMITER`), and preferably prefix each field with its length or escape the delimiter within field values. Ideally, retire the unseparated legacy branch entirely (or apply the delimited join regardless of `creation_date`) so no currently-created contract can produce a colliding hash between different `title`/`text` combinations.

### Proof of Concept
1. Offeror A composes contract #1 with `title = "Sale Agreement"`, `text = ""` and all other fields fixed (`creation_date`, `payer_address`, `arbiter_address`, `payee_address`, `amount`, `asset`).
2. Offeror A composes contract #2 with `title = "Sale Agreemen"`, `text = "t"` (one character moved from `title` to `text`), keeping every other field identical.
3. Because `getHashSrc()` joins the array with `""` for contracts dated before `NEW_HASH_DATE`, the concatenated source strings for #1 and #2 are byte-for-byte identical, so `getHash()` returns the same SHA-256 digest for both: [7](#0-6) 
4. A can send contract #2 (with subtly different wording) to a counterparty who believes they are looking at, or has previously reviewed/screenshotted, contract #1 — both produce the identical `contract.hash` that gets embedded as `contract_text_hash` in the on-chain `data` message and checked in `handleReceivedSigningUnit`, so the network/verification code cannot distinguish which text was actually agreed to.

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

**File:** arbiter_contract.js (L596-604)
```javascript

					// post a unit with contract text hash and send it for signing to correspondent
					var value = {"contract_text_hash": contract.hash, "arbiter": contract.arbiter_address, contacts_hash};
					var objContractMessage = {
						app: "data",
						payload_location: "inline",
						payload_hash: objectHash.getBase64Hash(value, true),
						payload: value
					};
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
