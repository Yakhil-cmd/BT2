Based on my investigation, `arbiter_contract.js` contains a direct analog of the reported vulnerability class.

### Title
Contract hash uses delimiter-less/delimiter-unsafe field concatenation, enabling hash collisions to forge arbiter contract terms - (File: arbiter_contract.js)

### Summary
`getHashSrc`/`getHash` in `arbiter_contract.js` compute the unique commitment hash for an arbiter contract by concatenating variable-length, attacker-controlled string fields (title, text, party names, addresses, amount, asset). For contracts created before `NEW_HASH_DATE` (currently **all** contracts, since `NEW_HASH_DATE` is set to a future date `2026-11-01` while today is 2026-09-15), the fields are joined with an empty separator (`join("")`), exactly the "packing differently sized/variable arguments without delimiters" bug class described in the external report. [1](#0-0) 

### Finding Description
`getHashSrc` builds the hash source string as:

```
[title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset].join("")
```

when `contract.creation_date <= NEW_HASH_DATE`. Because plain string concatenation with no separator (and no length prefixing) is used, two different sets of field values can produce an identical concatenated string and therefore an identical SHA-256 hash, mirroring the `abi.encodePacked` collision described in the report (e.g. `title="A", text="BC"` vs `title="AB", text="C"`, or shifting characters across the `payer_name`/`arbiter_address`/`payee_name` boundaries). `NEW_HASH_DATE` is currently `2026-11-01`, which is in the future relative to today, so the vulnerable no-delimiter branch is the one actually exercised by all newly created contracts right now. [2](#0-1) [3](#0-2) 

This is directly analogous to `prosaic_contract.js`'s `getHash`/`getHashV1`, which concatenate `title + text + creation_date` with no delimiter at all, unconditionally: [4](#0-3) 

The `text`/`title` fields for both contract types are peer-supplied (a counterparty in a bilateral device-to-device negotiation) and are not restricted from containing arbitrary characters that could straddle field boundaries. The resulting `hash` is used as the durable identifier for the contract, is shared with the counterparty/cosigners via `arbiter_contract_offer`/`arbiter_contract_shared`, and (for the prosaic contract case) is embedded on-chain as `contract_text_hash` inside a `data` message that is verified against the locally-stored contract on `handleReceivedSigningUnit`: [5](#0-4) 

### Impact Explanation
Because the hash is meant to be an irrefutable, unique commitment to a specific set of contract terms (title, text, payer/payee/arbiter addresses, amount, asset), a colliding pair of terms breaks that guarantee. A dishonest counterparty (payer, payee, or a party colluding with the arbiter) can craft two different term sets that hash identically, then later assert that the on-chain-anchored hash corresponds to a different textual agreement than the one actually negotiated. Since these contracts are specifically designed to produce dispute-resolvable, arbiter-verifiable proof of agreed terms (including `amount`/`asset`/`arbiter_address` in the arbiter-contract hash source), a successful collision can be used to misrepresent the terms an arbiter/adjudicator relies on when deciding fund release from the escrow-like shared address, leading to fund loss/misdirection for the honest counterparty.

### Likelihood Explanation
Exploitation only requires control over the free-text `title`/`text`/party-name fields supplied during contract negotiation between two devices — no special privileges, network position, or leaked keys are needed. Because the vulnerable no-delimiter code path is the one currently active for all contracts (the `NEW_HASH_DATE` cutover has not yet occurred), any user negotiating an arbiter or prosaic contract today is exposed. Constructing a colliding pair of strings is a standard SHA-256 preimage-independent exercise (choose overlapping boundaries), well within reach of a motivated counterparty, matching the ease demonstrated in the original report's PoC.

### Recommendation
Use a length-prefixed or type-tagged encoding for every field before hashing (as `string_utils.js`'s `getSourceString`/`getJsonSourceString` already do correctly elsewhere in the codebase, via `STRING_JOIN_CHAR` prefixing each field with its type marker), instead of naive concatenation or a delimiter string that isn't proven absent from user input. Concretely:
- Replace the `join("")` branch in `arbiter_contract.js`'s `getHashSrc` and the `contract.title + contract.text + contract.creation_date` concatenation in `prosaic_contract.js`'s `getHash`/`getHashV1` with `objectHash.getBase64Hash({title, text, creation_date, ...})`, which already uses the collision-resistant `getSourceString` encoding.
- For the "new" `DELIMITER`-based path in `arbiter_contract.js`, explicitly reject/escape any field value containing the delimiter substring `"[|#|]"` before hashing, or better, also switch to `objectHash.getBase64Hash`. [6](#0-5) 

### Proof of Concept
1. Party A negotiates an arbiter contract with `title="A"`, `text="BC..."` and other fields fixed.
2. Party A also crafts an alternate term set with `title="AB"`, `text="C..."` (shifting one character from `text` into `title`) while keeping every other field identical.
3. Because `getHashSrc` uses `join("")` with no delimiter, `getHash(contractA) === getHash(contractAlt)`.
4. Party A shares `contractA` (hash `H`) as the "agreed" version with the counterparty/arbiter, later produces `contractAlt` as the "true" record during a dispute, both hashing to `H`, so a verifier relying solely on `objectHash`-style hash equality (as in `prosaic_contract.js`'s `handleReceivedSigningUnit`, `payload.contract_text_hash !== contract.hash`) cannot distinguish which text was actually agreed upon. [7](#0-6)

### Citations

**File:** arbiter_contract.js (L17-19)
```javascript
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

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
