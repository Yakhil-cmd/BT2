## Title
Ambiguous unsigned-field concatenation in prosaic/arbiter contract hashing enables contract-content collision and forged `contract_text_hash` matches - (File: `prosaic_contract.js`, `arbiter_contract.js`, `wallet.js`)

### Summary
The Gitea advisory's root cause is that a security-relevant value (an HMAC) is derived by concatenating raw, variable-length fields without delimiters or length-prefixing, so two different field tuples can yield an identical digest, letting an attacker rewrite one signed context into another. Ocore's private-contract subsystem contains the same class of bug: `prosaic_contract.getHash()` and the legacy branch of `arbiter_contract.getHashSrc()` build the content hash by concatenating `title`, `text`, and `creation_date` (and other fields) as raw strings with **no delimiter and no length-prefixing**, then that hash is trusted as the sole integrity binding between a device-message-negotiated contract and the `contract_text_hash` embedded in an on-DAG signed `data` message.

### Finding Description
`prosaic_contract.js` computes the contract hash as: [1](#0-0) 

`contract.title + contract.text + contract.creation_date` with no separator. Because `title` and `text` are attacker/peer-controlled arbitrary strings, moving a suffix of `title` into the prefix of `text` (or shifting characters across the `text`/`creation_date` boundary) produces a different logical contract with an **identical SHA-256 digest** — an exact structural analog of the Gitea `artifactName`/`taskID`/`artifactID` concatenation collision.

The legacy branch of `arbiter_contract.js` has the identical flaw, still reachable for any contract with `creation_date <= NEW_HASH_DATE`: [2](#0-1) 
Note the ternary: only contracts dated after `NEW_HASH_DATE` use a delimiter (`exports.DELIMITER`); the `else` branch still does `.join("")`, i.e., raw concatenation of `title`, `text`, `creation_date`, `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset` with no boundaries.

This hash is not merely a lookup key — it is used as the authenticity check binding an off-chain negotiated contract to an on-DAG cryptographically signed unit. In `prosaic_contract.js`, `handleReceivedSigningUnit()` accepts a contract as validly signed if the `contract_text_hash` in a DAG unit's `data` payload matches `contract.hash`: [3](#0-2) 

Similarly, `wallet.js` validates the arbiter dispute flow by recomputing `arbiter_contract.getHash(...)` from peer-supplied fields and comparing to a `contract_hash`/`payload.contract_text_hash`: [4](#0-3) 

And on ordinary contract offer/share, the same unstructured hash is the sole authenticity check accepted from an untrusted peer device message: [5](#0-4) [6](#0-5) 

Because `title`/`text` are free-form strings under the counterparty's control (an "private-payment counterparty" in the threat model), a malicious counterparty can construct two distinct `(title, text, creation_date, ...)` tuples whose raw concatenation is byte-identical, i.e., a genuine collision requires only that `title_A + text_A == title_B + text_B` (with `creation_date` untouched) — e.g. `title_A="Rent Payment"`, `text_A="December"`, vs. `title_B="Rent Paymen"`, `text_B="tDecember"`. Both hash identically. This is much easier to exploit than a SHA-256 preimage break: it's a pure boundary-shift, not a cryptographic weakness of SHA-256 itself, exactly as the Gitea report describes for its HMAC construction.

This differs from the safe pattern used elsewhere in the codebase: `string_utils.getSourceString()` — used for unit/AA/device-message hashing — explicitly guards against this class of bug by type/length-prefixing every field and rejecting embedded join-character bytes: [7](#0-6) 
The contract-hash functions in `prosaic_contract.js` and the legacy path of `arbiter_contract.js` bypass this safe hashing utility entirely.

### Impact Explanation
An untrusted counterparty (in the "private payment / private contract" negotiation flow, reachable by anyone who can pair a device and exchange `prosaic_contract_offer` / `arbiter_contract_offer` / `arbiter_contract_shared` messages) can present a counterfeit `title`/`text` pair that collides with the hash of a previously agreed contract. Consequences:
- **Contract substitution / integrity loss**: `handleReceivedSigningUnit()` will bind an on-DAG signed unit's `contract_text_hash` to attacker-substituted contract text, since the hash check is the only authenticity binding — the victim's wallet UI/records could display or act on different contract terms than what was actually cryptographically committed to in the DAG.
- **Dispute/appeal manipulation**: `wallet.js`'s `arbiter_dispute_request` handler recomputes `getHash()`/`getContactsHash()` from peer-supplied fields to authenticate dispute content sent to an arbiter; a colliding tuple lets an attacker present altered contract terms (title/text/party names) to the arbiter service while passing the `expectedContractHash === body.contract_hash` and `payload.contract_text_hash` checks, potentially causing a dispute to be adjudicated over falsified terms that still validates against the genuine committed hash.
- This is a private, counterparty-mediated contract feature (financial commitment tied to an actual payment/arbiter address and amount), so successful substitution of terms is a concrete integrity/fund-dispute-outcome issue, not merely cosmetic.

### Likelihood Explanation
Medium-to-High: any two-party contract negotiation counterparty already fully controls `title` and `text` (free text fields) and can trivially engineer a boundary-shift collision without any cryptographic effort — it requires no key compromise, no brute force, and works deterministically for any first tuple by simply moving characters across the field boundary. The only constraint is that party names, dates, and amounts must be unchanged in the classic no-delimiter path (or must be engineered for the newer delimited `arbiter_contract.js` path, which is safe by construction) — but `prosaic_contract.js` has **no delimiter path at all**, so it is unconditionally vulnerable for every contract, not just legacy-dated ones.

### Recommendation
- In `prosaic_contract.js`, replace raw string concatenation in `getHash()` with a delimited or structured encoding (e.g., `string_utils.getSourceString({title, text, creation_date})`, mirroring the fix already partially applied in `arbiter_contract.js` via `exports.DELIMITER`).
- Remove or retire the legacy `join("")` branch in `arbiter_contract.getHashSrc()` for all newly created contracts; if backward compatibility for old contracts is required, restrict acceptance of the unsafe legacy hash format to already-existing, previously stored (not newly negotiated) contract hashes.
- Ensure the delimiter (or a chosen JSON-based canonicalization) itself cannot appear inside `title`/`text`, or use length-prefixed encoding as `string_utils.getSourceString` does.
- Audit all places comparing peer-supplied/`contract_text_hash`-style values (`wallet.js` lines 625, 645, 663, 780-806, `prosaic_contract.js` line 173) to ensure they use the corrected canonical hash.

### Proof of Concept
1. Alice and Bob negotiate a prosaic contract via `prosaic_contract.createAndSend()`, hash computed as `getHash({title:"Rent Payment", text:"December", creation_date:"2026-09-01 00:00:00"})`.
2. A malicious Bob (or a MITM-capable correspondent controlling the device message) instead sends contract fields `title:"Rent Paymen"`, `text:"tDecember"`, same `creation_date` in a follow-up `prosaic_contract_shared`/DAG `data` payload with `contract_text_hash` set to the same value.
3. Because `getHash()` = `sha256(title+text+creation_date)`, both tuples hash identically: `"Rent Payment"+"December"` === `"Rent Paymen"+"tDecember"` as raw concatenation.
4. `handleReceivedSigningUnit()` (`prosaic_contract.js:173`) accepts the DAG unit's payload as matching contract `contract.hash`, even though the semantic contract terms differ from what the victim believes was agreed and signed.
5. The equivalent applies to `arbiter_contract.js`'s legacy (`creation_date <= NEW_HASH_DATE`) hash path and to the `wallet.js` `arbiter_dispute_request` recomputation checks at lines 767-781 and 797-806, enabling a counterparty to submit altered contract terms to the arbiter while still matching the previously committed hash.

### Citations

**File:** prosaic_contract.js (L98-104)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}

function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```

**File:** prosaic_contract.js (L159-176)
```javascript
function handleReceivedSigningUnit(contract, unit, retry_count = 0) {
	db.query("SELECT 1 FROM unit_authors WHERE unit=? AND address=?", [unit, contract.shared_address], async function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`signing tx ${unit} not found in db after 10 retries, giving up`);
			console.log(`signing tx ${unit} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSigningUnit, 30000, contract, unit, retry_count + 1);
		}
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

**File:** wallet.js (L617-627)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
```

**File:** wallet.js (L658-666)
```javascript
			case 'arbiter_contract_shared':
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.peer_pairing_code || !ValidationUtils.isPositiveInteger(body.amount))
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.arbiter_address) )
					return callbacks.ifError("either peer_address or address or arbiter_address or shared_address are not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
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

**File:** string_utils.js (L11-60)
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
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
}
```
