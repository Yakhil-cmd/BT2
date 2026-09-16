### Title
Ambiguous, delimiter-free hash of contract terms in `prosaic_contract.js`/`arbiter_contract.js` allows different (title, text, amount, asset) inputs to collide on the same `contract_text_hash` - (File: `prosaic_contract.js`, `arbiter_contract.js`)

### Summary
`prosaic_contract.getHash()` and the legacy branch of `arbiter_contract.getHashSrc()` build the hash that binds two paired-device counterparties to a contract by naively concatenating user-controlled fields (`title`, `text`, `creation_date`, party names, `amount`, `asset`) with either no separator at all or a fixed separator that is never checked against the input strings, then hashing the result. This is the same root-cause class as the reported `MetaTxLib` bug: structured, variable-length fields are serialized ambiguously before hashing, so distinct logical inputs can produce an identical hash.

### Finding Description
`prosaic_contract.js` `getHash()`: [1](#0-0) 
concatenates `contract.title + contract.text + contract.creation_date` directly with **no delimiter whatsoever**. Since `title` and `text` are free-form strings supplied by either negotiating party over a device (paired-wallet) channel, any byte sequence can be redistributed across the `title`/`text` boundary while producing the exact same SHA-256 digest, e.g. `title="AB", text="C"` hashes identically to `title="A", text="BC"`.

`arbiter_contract.js` `getHashSrc()` has the same defect for contracts created before `NEW_HASH_DATE` (`'2026-11-01'`), which — given today's date — is still the **currently active code path**: [2](#0-1) 
For these contracts the fields `title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset` are joined with `""` (empty string), again with no unambiguous field separator. Even the "fixed" branch (`creation_date > NEW_HASH_DATE`) only inserts a literal delimiter `"[|#|]"` without validating that user-supplied `title`/`text`/party-name fields cannot themselves contain that delimiter sequence, so the ambiguity is only mitigated, not eliminated, by cross-checking. `getContactsHash()` has the identical pattern, joining `payer_contact_info`, `payer_pairing_code`, `payee_contact_info`, `payee_pairing_code` with a bare `"|"` separator that is never validated against the (attacker-influenced) `contact_info`/`pairing_code` strings: [3](#0-2) 

This is functionally identical to the reported bug class: instead of using a canonical, unambiguous encoding of a structured record (as the codebase does correctly elsewhere via `string_utils.getSourceString`/`getJsonSourceString`, which type-tag every field and explicitly forbid embedding the join character — see [4](#0-3) ), these contract-hashing helpers hand-roll concatenation without boundary protection, defeating the purpose of the hash as a commitment to a specific set of contract terms.

The resulting `hash`/`getContactsHash()` output is what gets embedded on-chain as `contract_text_hash`/`contacts_hash` in the `data` message that a shared (multisig) address is later required to match before the contract is treated as mutually signed: [5](#0-4) 
and is likewise what the peer's local record is checked against when a `unit` is received for a prosaic contract: [6](#0-5) 

### Impact Explanation
Because `amount` and `asset` are included, unseparated, inside the same hash as free-text `title`/`text`, a malicious counterparty in a private (paired-device) contract negotiation can construct two different contracts — e.g., one showing a small `amount`/benign `asset` string and one where digits from `amount` bleed into `asset` (or vice versa) to represent a different payment amount/asset — that hash to the identical `contract_text_hash`. Since the hash is the only cryptographic anchor tying the human-negotiated terms to what is later verified on-chain (`contract_text_hash` in the `data` message) and to what triggers `status = "signed"` / dispute resolution by the arbiter, an attacker can present a victim with one version of the terms for review/signing while having a differently-split but hash-identical version accepted as canonical downstream, or construct a colliding contract whose committed hash matches a contract the victim already approved. This directly affects the integrity of the payment terms enforced between the two private-payment counterparties and can enable a party to redirect or misrepresent the agreed `amount`/`asset`, leading to fund loss for the counterparty who trusted the hash as a binding, unambiguous commitment to the terms they reviewed.

### Likelihood Explanation
Both `prosaic_contract.js` and `arbiter_contract.js` are reachable directly by any paired device counterparty (the negotiation is peer-to-peer via `device.sendMessageToDevice`), requiring no special privileges beyond being paired with the victim's wallet — squarely within the "paired device" and "private-payment counterparty" reachable surface. The vulnerable, delimiter-free `getHashV1`-style legacy path in `arbiter_contract.js` is the currently active branch given the `NEW_HASH_DATE` guard is set in the future relative to the present date, and `prosaic_contract.js`'s only `getHash()` implementation has no delimiter at all, so the bug is live in the current codebase without requiring any special conditions.

### Recommendation
Replace ad-hoc string concatenation in `getHash`, `getHashSrc`, `getHashV1`, and `getContactsHash` with the canonical structured hashing already used elsewhere in the codebase (`objectHash.getBase64Hash`/`string_utils.getSourceString` or `getJsonSourceString`), which type-tags and length/character-delimits every field and rejects embedded join characters, guaranteeing that no two distinct sets of (title, text, creation_date, party info, amount, asset) can hash to the same digest. If a plain-string join must be kept, reject any input field that contains the delimiter and/or encode each field with an explicit length prefix before concatenation.

### Proof of Concept
1. Party A proposes a prosaic/arbiter contract to Party B with `title = "Pay ", text = "100 USD"`.
2. Party A instead stores/serves a different `title = "Pay 1", text = "00 USD"` to another party or system that only checks the hash.
3. `crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date).digest("base64")` (`prosaic_contract.js` line 99) produces the identical digest for both splits, since `"Pay " + "100 USD" === "Pay 1" + "00 USD"`.
4. Any downstream verification comparing only `contract.hash`/`contract_text_hash` (e.g., `prosaic_contract.js` lines 167-175, `arbiter_contract.js` lines 669-676) cannot distinguish the two logically different contract records, allowing the terms shown to one party to diverge from the terms recorded/enforced for signature verification while the hash still matches.

### Citations

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L167-175)
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

**File:** arbiter_contract.js (L669-676)
```javascript
		const objUnit = await storage.readUnit(unit);
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported signing unit ${unit}`);
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
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
