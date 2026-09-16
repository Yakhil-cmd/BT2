Good — the data feed \n-injection path is already properly guarded (validation.js:1936-1943 and aa_validation.js:100-110 both reject `\n` in feed_name/value). So that's not a valid analog; it's already fixed.

The real analog is the **prosaic contract hash** in `prosaic_contract.js`:### Title
Delimiter-less field concatenation in prosaic/arbiter contract hash allows content-boundary forgery with a valid hash - (File: prosaic_contract.js)

### Summary
`prosaic_contract.js` computes the integrity hash of a peer-to-peer prosaic contract by naively concatenating `title`, `text`, and `creation_date` with **no separator and no escaping**, exactly the "improper handling of special characters when building a structured/hashed value from untrusted string fields" bug class described in the CloudFront advisory. Because there is no delimiter between fields, many different `(title, text)` pairs hash to the same value, so the `hash` field no longer uniquely commits to the content it is supposed to authenticate.

### Finding Description
`getHash()` in [1](#0-0)  builds the source string as plain string concatenation:
```js
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```
Unlike the codebase's own canonical hashing helpers (`getSourceString` in [2](#0-1)  and `getJsonSourceString`), which explicitly reject a `STRING_JOIN_CHAR` embedded in any field before concatenation to prevent this exact class of ambiguity, `getHash()` performs raw string addition with zero field-boundary protection.

`title` and `text` are fully attacker-controlled, arbitrary-length strings supplied by a paired device peer in the `prosaic_contract_offer` / `prosaic_contract_shared` messages, handled in [3](#0-2)  and [4](#0-3) :
```js
case 'prosaic_contract_offer':
    ...
    if (body.hash !== prosaic_contract.getHash(body)) {
        if (body.hash === prosaic_contract.getHashV1(body))
            return callbacks.ifError("received prosaic contract offer with V1 hash");	
        return callbacks.ifError("wrong contract hash");
    }
    ...
    prosaic_contract.store(body);
```
Because `title` and `text` are concatenated without a separator, a sender can shift characters across the `title`/`text` boundary (e.g. `title="Pay 100 to Alice", text=""` vs. `title="Pay 1", text="00 to Alice"`) and still produce an identical hash for `creation_date` held constant. The same commitment (`hash`) is later relied upon on-chain: when the contract is signed, a `data` message with `contract_text_hash` is posted and compared for equality with the stored `contract.hash` in [5](#0-4) :
```js
if (payload.contract_text_hash !== contract.hash)
    return console.log(`data message payload does not match contract ${contract.hash} ...`);
```
This on-chain hash is the only anchor that binds the shared contract text to the payment/shared address created via `deriveSharedAddress()`. The identical structural flaw exists in the "new" arbiter contract hash format in [6](#0-5) , which joins fields with a fixed literal `DELIMITER = "[|#|]"` ( [7](#0-6) ) but never validates that attacker-controlled fields (`title`, `text`, `my_party_name`, `peer_party_name`) do not themselves contain that delimiter substring — again permitting field-boundary forgery, unlike `getSourceString`'s explicit `00 byte in string value` guard.

### Impact Explanation
The `hash` is used as the primary lookup key/identifier for a prosaic (and arbiter) contract stored across paired devices and later relied upon at signing time and on-chain to prove "this is the text both parties agreed to." Because the concatenation is not boundary-safe, a malicious counterparty can:
- Present two different `(title, text)` documents that hash identically, undermining any later verification/dispute-resolution reliance on the `contract.hash`/`contract_text_hash` binding as a unique, tamper-evident commitment to specific contract text.
- Combined with the fact that `hash` is used as a DB primary lookup key (`getByHash`) shared and re-shared between cosigner devices (`shareContractToCosigners`, `store`), this can allow a peer to substitute or desynchronize what different parties believe was agreed to while all validations of `body.hash === prosaic_contract.getHash(body)` still pass.

This matches CWE-116/CWE-20 (Improper Encoding/Escaping of Output, Improper Input Validation): the vulnerability is in the canonicalization of user-supplied fields into a hashed value used for integrity commitments feeding into payment/contract authorization flows (prosaic and arbiter contracts, which govern shared-address definitions and dispute resolution and hence fund release).

### Likelihood Explanation
Trivially reachable by an unprivileged paired-device peer: any correspondent that a wallet is paired with can send a crafted `prosaic_contract_offer` (or `arbiter_contract_offer`) device message with attacker-chosen `title`/`text`/party-name strings; no special privilege beyond normal pairing is required. Exploitation is a simple string-splitting exercise with no cryptographic effort.

### Recommendation
Replace ad-hoc concatenation in `prosaic_contract.getHash()` (and the "new" branch of `arbiter_contract.getHashSrc()`) with the codebase's existing canonical serialization helpers `getSourceString`/`getJsonSourceString` (or equivalently hash each field separately, e.g. `sha256(sha256(title) || sha256(text) || sha256(creation_date))`), so that field boundaries cannot be shifted by controlling field contents. If a literal delimiter is retained (as in `arbiter_contract.DELIMITER`), explicitly reject any field value that contains the delimiter substring before joining, mirroring the `00 byte in string value` check already used in `string_utils.getSourceString`.

### Proof of Concept
1. Attacker pairs with victim's wallet as a normal device correspondent.
2. Attacker sends contract A: `{title: "Pay 100 to Alice", text: "", creation_date: "2026-09-15 00:00:00", hash: getHash(A)}` via `prosaic_contract_offer`.
3. Attacker (or a colluding second identity) later sends contract B: `{title: "Pay 1", text: "00 to Alice", creation_date: "2026-09-15 00:00:00", hash: getHash(B)}`.
4. Since `getHash(A) === getHash(B)` (identical concatenation `"Pay 100 to Alice" + "" + creation_date` == `"Pay 1" + "00 to Alice" + creation_date`), both pass the `body.hash !== prosaic_contract.getHash(body)` check in `wallet.js`'s `prosaic_contract_offer` handler despite representing differently-partitioned (and potentially differently-rendered/interpreted) contract content, demonstrating the field-boundary collision in the hash used as the contract's unique integrity anchor.

### Citations

**File:** prosaic_contract.js (L98-100)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}
```

**File:** prosaic_contract.js (L159-177)
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
}
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

**File:** wallet.js (L455-481)
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
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.my_address], function(rows) {
					if (!rows.length)
						return callbacks.ifError("contract does not contain my address");
					delete body.shared_address;
					prosaic_contract.store(body);
					var chat_message = "(prosaic-contract:" + Buffer.from(JSON.stringify(body), 'utf8').toString('base64') + ")";
					eventBus.emit("text", from_address, chat_message, ++message_counter);
					callbacks.ifOk();
				});
				break;
```

**File:** wallet.js (L483-502)
```javascript
			case 'prosaic_contract_shared':
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address))
					return callbacks.ifError("either peer_address or address is not valid in contract");
				if (body.hash !== prosaic_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address shared with your device");
						prosaic_contract.store(body);
						callbacks.ifOk();
					}
				);
				break;
```

**File:** arbiter_contract.js (L19-19)
```javascript
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
