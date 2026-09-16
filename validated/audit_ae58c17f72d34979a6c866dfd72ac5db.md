### Title
Delimiter-less contract-hash construction allows arbiter-contract field-boundary collisions - (File: arbiter_contract.js)

### Summary
Symfony's CVE-2019-10911 stemmed from concatenating multiple values into a single hash input without a separator, letting an attacker shift the boundary between adjacent fields to forge a different, colliding identity token. `arbiter_contract.js` contains the same anti-pattern: the legacy branch of `getHashSrc()` builds the `contract.hash` (the unique, trust-anchoring identifier for an arbiter contract) by joining several attacker-influenced strings with **no delimiter at all**.

### Finding Description
`getHashSrc()` computes the source string that is hashed into `contract.hash`: [1](#0-0) 

For contracts created on/before `exports.NEW_HASH_DATE` (`'2026-11-01'`, i.e. still in effect as of the current date), the source string is built with `.join("")` — plain string concatenation with **zero separator** — over `title`, `text`, `creation_date`, `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset`: [2](#0-1) 

`title`, `text`, `my_party_name`/`peer_party_name` are free-form strings supplied by the contract-offering party (an unprivileged unit/AA-adjacent peer in the messaging protocol) when creating the offer via `createAndSend()`: [3](#0-2) 

Because these fields are simply concatenated, moving trailing characters of `title` into the leading characters of `text` (or of `payer_name` into `arbiter_address`, etc.) produces a **different logical contract with an identical concatenated source string**, and therefore an identical `sha256`-based `contract.hash`. This is the exact bug class in the advisory: hashing `field1 + field2` without a boundary marker lets `field1="AB", field2="C"` collide with `field1="A", field2="BC"`.

This is significant because `contract.hash` is treated as an authenticator of contract content throughout the flow:
- It is used to key the on-chain data message `contract_text_hash` that the shared address's payment definition and dispute flow rely on to prove "this signed unit corresponds to this specific contract": [4](#0-3) 
- Peers re-validate a purported signing unit strictly by comparing `payload.contract_text_hash !== contract.hash` (and the separately-hashed `contacts_hash`), not by re-deriving/binding every individual field: [5](#0-4) 
- The arbiter's dispute resolution keys off `"CONTRACT_" + contract.hash` in a data feed, and the shared-address definition itself embeds `contract.hash` as the data-feed lookup key that unlocks funds to the dispute winner: [6](#0-5) 

An attacker who controls the contract-offering side (`createAndSend`) can craft two different `title`/`text`/`party_name` field splits that hash to the same `contract.hash` value, e.g. present a benign-looking contract to build trust or to an arbstore/UI, while a different combination of terms produces the identical hash used for on-chain binding, dispute submission (`encrypted_contract` sent to the arbiter via `/api/dispute/new`), and shared-address salt input.

### Impact Explanation
`contract.hash` is the sole cryptographic binding between the human-readable contract terms and the money-moving shared address / dispute mechanism. If two distinct contracts (different amounts owed in kind, different party names, different text) can be engineered to share the same hash, an arbiter or counterparty could resolve, sign, or pay against terms different from what was actually agreed, or a party could later repudiate/substitute the visible contract content while the on-chain `contract_text_hash` check still passes. This directly maps to unauthorized fund movement / dispute-resolution manipulation within the arbiter-contract payment flow, which the ocore code itself flags as fund-loss-sensitive (see the explicit anti-collision comment for shared address definitions at line 523 protecting against a related but different attack). Confidence is bounded by the fact that `amount` is numeric (harder, not impossible, to exploit for boundary-shifting since digits are limited) and `creation_date` has a fixed format, which constrains but does not eliminate exploitable collisions among the free-text fields (`title`, `text`, `my_party_name`/`peer_party_name`, and `arbiter_address` boundary).

### Likelihood Explanation
The contract-offering party fully controls `title`, `text`, `my_party_name` (and effectively influences `peer_party_name` display, since it is just a label) at contract-creation time, so no privileged access is needed — only participation as one side of an arbiter contract negotiation, which is available to any wallet user. Exploitation only requires finding a string split point that produces a byte-identical concatenation, which is a controlled, deterministic search over string boundaries (not a cryptographic hash break) — significantly easier than the original CVE's remember-me forgery. The `exports.DELIMITER = "[|#|]"` and the guarded `NEW_HASH_DATE` branch show the ocore authors already recognized the delimiter problem and added a fix, but the legacy delimiter-less path remains reachable for any contract with `creation_date <= NEW_HASH_DATE`, which — given `NEW_HASH_DATE` is set in the future (2026-11-01) — is the currently active code path for all newly created contracts as of today.

### Recommendation
Force use of the delimited `getHashSrc` branch immediately (set `NEW_HASH_DATE` to a date in the past, or remove the legacy branch entirely) so every field is joined with `exports.DELIMITER`, and ensure the delimiter itself cannot appear inside any of the joined fields (reject/escape occurrences of `exports.DELIMITER` in `title`, `text`, `party_name`, `asset` the same way `string_utils.js`'s `getSourceString` explicitly rejects the `STRING_JOIN_CHAR` inside strings): [7](#0-6) 
Apply the same delimiter-injection check to `getContactsHash()`, which similarly joins fields with a bare `"|"` without validating that `contact_info`/`pairing_code` cannot contain `"|"`: [8](#0-7) 

### Proof of Concept
1. Party A offers Contract X: `title="Sale of car"`, `text="123 for $500"`, with `payer_name="Al"`, `arbiter_address=AD`, `payee_name="Bob"`, `amount=500`, `asset="null"`.
2. Compute `getHashSrc` (legacy branch): `"Sale of car" + "123 for $500" + creation_date + "Al" + AD + "Bob" + "500" + "null"`.
3. Party A crafts Contract Y with `title="Sale of car1"`, `text="23 for $500"` (one character moved across the title/text boundary), same `creation_date`, `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset`.
4. `getHashSrc(Y)` produces the byte-identical string to `getHashSrc(X)` because `.join("")` has no separator between `title` and `text`, so `getHash(X) === getHash(Y)`.
5. Party A sends Contract Y's `contract.hash` (identical to X's) to the arbstore in a dispute (`/api/dispute/new`, `encrypted_contract` and `contract_hash` fields at lines 277–296) while showing Contract X's terms to the counterparty, or vice-versa, causing terms confusion at the arbiter/dispute-resolution and payload-validation layers that trust `contract_text_hash === contract.hash` as sufficient proof of content integrity.

### Citations

**File:** arbiter_contract.js (L21-27)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
	device.getOrGeneratePermanentPairingInfo(pairingInfo => {
		objContract.my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
		db.query("INSERT INTO wallet_arbiter_contracts (hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, my_contact_info, my_pairing_code, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 0, objContract.creation_date, objContract.ttl, status_PENDING, objContract.title, objContract.text, objContract.my_contact_info, objContract.my_pairing_code, JSON.stringify(objContract.cosigners) ... (truncated)
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

**File:** arbiter_contract.js (L465-480)
```javascript
				var arrDefinition =
					["or", [
						["and", [
							["address", offeror_address],
							["address", acceptor_address]
						]],
						[], // placeholders [1][1]
						[],	// placeholders [1][2]
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
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

**File:** arbiter_contract.js (L670-681)
```javascript
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported signing unit ${unit}`);
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
		const author = objUnit.authors.find(author => author.address === contract.shared_address);
		const signing_paths = Object.keys(author.authentifiers);
		const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
		if (!isMutuallySigned)
			return console.log(`signing unit ${unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
```

**File:** string_utils.js (L17-20)
```javascript
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
```
