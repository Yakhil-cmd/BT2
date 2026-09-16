### Title
Ambiguous field-boundary hashing in prosaic contract identifier allows byte-shifting between `title` and `text` - (File: prosaic_contract.js)

### Summary
`prosaic_contract.js`'s `getHash()` builds the contract identifier by naive string concatenation of `title`, `text`, and `creation_date` with no delimiter or length-prefixing before hashing, mirroring the `DKGResultVerification.verify` unsafe-packing bug class (`abi.encodePacked(groupPubKey, misbehaved)`), where variable-length fields can be shifted across the boundary while producing the same digest.

### Finding Description
`getHash(contract)` computes `sha256(contract.title + contract.text + contract.creation_date)` [1](#0-0)  and the legacy `getHashV1` does the same via `objectHash.getBase64Hash` [2](#0-1) . Because `title` and `text` are attacker/counterparty-controlled free-text fields concatenated directly with no separator, a party crafting the contract offer can choose `title'`/`text'` such that `title' + text' === title + text` for a different split point, yielding an identical hash for materially different (title, body) pairs. This is the same unsafe-packing pattern flagged in the external report for `DKGResultVerification.verify`, where `groupPubKey` and `misbehaved` are concatenated without a length check or salt [3](#0-2) .

This contrasts with the codebase's general-purpose hashing utility `getSourceString`, which explicitly type-prefixes and delimiter-separates every field and rejects any field containing the join character to prevent exactly this class of ambiguity [4](#0-3) . `prosaic_contract.js` bypasses that safe utility and hashes raw concatenated strings instead.

The resulting `contract.hash` is later used as the sole integrity check tying an on-chain signing unit's `data` message payload to the negotiated contract terms: `handleReceivedSigningUnit` accepts a unit as the valid execution of the contract purely because `payload.contract_text_hash === contract.hash`, without re-validating `title`/`text` against the unit content [5](#0-4) .

### Impact Explanation
Because the hash is used as a trust anchor equating "this signing unit corresponds to this specific contract text" between two private-payment counterparties, an ambiguous boundary allows one party to present a `title`/`text` pair to the peer's device (`prosaic_contract_offer` / stored contract) that hashes identically to a different, unintended `title`/`text` split. This can be leveraged to make the receiving wallet associate a signed on-chain payment or reference unit with a contract whose displayed terms differ subtly from what was actually agreed/verified, undermining the intended non-repudiation/agreement-matching guarantee of the feature.

### Likelihood Explanation
No cryptographic break is required — only careful selection of `title`/`text` content so that the shifted concatenation reproduces the same string, which is a low-effort manipulation fully within control of either negotiating party (the contract offeror). The vulnerable code path (`getHash`/`getHashV1`) is reached whenever a prosaic contract is created, shared, or matched against a signing unit, i.e., on every normal wallet-to-wallet contract exchange.

### Recommendation
Replace the raw concatenation in `getHash`/`getHashV1` with the codebase's safe hashing utilities that already solve this problem, e.g. `objectHash.getBase64Hash({title, text, creation_date})` (which internally uses `string_utils.getSourceString`/`getJsonSourceString` with type-prefixing, delimiter separation, and delimiter-collision rejection) instead of manual field concatenation, so that no combination of `title`/`text`/`creation_date` values can produce a colliding hash for a different logical split.

### Proof of Concept
1. Party A proposes contract offer with `title = "Pay"`, `text = "100 to Bob"`, `creation_date = "2026-09-15"`.
2. `getHash` computes `sha256("Pay" + "100 to Bob" + "2026-09-15")`.
3. Party A alternatively crafts `title = "Pay1"`, `text = "00 to Bob"` (same concatenation `"Pay100 to Bob"`), producing the identical hash via `getHash` [1](#0-0) .
4. Either representation matches the same `contract.hash` used later by `handleReceivedSigningUnit` to bind an on-chain unit's `contract_text_hash` to the negotiated terms [6](#0-5) , letting the two parties (or a re-presenting counterparty) disagree on which literal title/text pair the signed unit actually corresponds to while the hash check silently passes.

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
