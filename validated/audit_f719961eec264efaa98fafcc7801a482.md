### Title
Arbiter contract hash uses ambiguous field concatenation without delimiters, enabling contract-terms forgery collisions - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` computes a commitment hash over the contract terms (`title`, `text`, `creation_date`, party names, `arbiter_address`, `amount`, `asset`) that peers use to verify they are agreeing to identical contract terms. `getHashSrc` selects between two encodings based on `contract.creation_date` compared to `exports.NEW_HASH_DATE` [1](#0-0) . The "old" branch joins all fields with `.join("")` — plain string concatenation with no delimiter, i.e. the same unsafe pattern as `abi.encodePacked` on dynamic-length fields that the external report flags as producing ambiguous/malformed encodings. Because `exports.NEW_HASH_DATE = '2026-11-01'` [2](#0-1)  and contracts are timestamped with the current date at creation time (`objContract.creation_date = new Date().toISOString()...`) [3](#0-2) , every contract created before 2026-11-01 (i.e., right now) falls into the vulnerable delimiter-less branch.

### Finding Description
`getHashSrc` builds the hash preimage two different ways:
```
contract.creation_date > exports.NEW_HASH_DATE
   ? [...].join(exports.DELIMITER)   // safe, delimited
   : [...].join("")                  // unsafe, no delimiter
``` [4](#0-3) 

In the unsafe branch, all the string fields (`title`, `text`, `payer_name`, `payee_name`, etc.) are concatenated with no separator between them. This is precisely the class of bug the external report describes for `abi.encodePacked`: concatenating multiple dynamic-length values without a delimiter creates a preimage where the field boundaries are ambiguous. Two different sets of `(title, text)` values can produce byte-identical concatenated strings (e.g. `title="AB", text="C"` vs `title="A", text="BC"`), yielding the identical SHA-256 hash via `getHash()` [5](#0-4) .

This hash is the sole cross-device integrity check for contract terms exchanged between peer wallets. `wallet.js` verifies received offers/shares strictly by recomputing and comparing this hash against the `prosaic_contract`-style hash check pattern (analogous check used for both `prosaic_contract` and `arbiter_contract`), and `respond()`/`store()` persist and act on the contract fields keyed by this `hash` without any additional integrity binding of the individual `title`/`text` boundaries [6](#0-5) . Since `hash` is the identifier used to fetch (`getByHash`), respond to, and share contracts to cosigners/peers, any place that trusts "same hash ⇒ same terms" is exposed to the ambiguity.

By contrast, the codebase's general-purpose hashing utility `getSourceString` explicitly guards against this ambiguity class by prefixing every value with a type tag and joining with an explicit `STRING_JOIN_CHAR` (`\x00`), and even throws if that character appears inside a string value [7](#0-6) . The fixed arbiter-contract branch adopts a similar mitigation (an explicit `DELIMITER` constant) [8](#0-7) , confirming that the delimiter-less branch was the recognized defect — the same fix pattern referenced in the external report ("use type/structure safe encoding instead of raw concatenation").

The critical detail is that the safe branch is gated by `contract.creation_date > exports.NEW_HASH_DATE`, and `NEW_HASH_DATE` is set to `'2026-11-01'`. Since `createAndSend` stamps new contracts with `new Date().toISOString()` at creation time, and the current date is 2026-09-15, every contract created today (and until November 2026) is computed with the vulnerable, delimiter-less encoding [9](#0-8) . The mitigation is effectively dormant for all currently-created contracts.

### Impact Explanation
An arbiter contract commits the payer, payee, arbiter, amount, asset, and free-text contract terms (`title`, `text`) that a shared/escrow address and later payment/resolution are based on. If a malicious counterparty (the "private-payment counterparty" reachable actor per scope) can construct alternate `(title, text)` pairs whose concatenation collides with an honestly-agreed pair under the same other fields, they can present, store, or later reference contract terms different from what the counterparty believed they agreed to, while the `hash` (used as the primary key and cross-device identifier for the contract) stays identical. Because `hash` is the trust anchor used across `getByHash`, `respond`, `store`, and `shareContractToCosigners`/`shareUpdateToPeer` flows, this can lead to a dispute where the arbiter, cosigners, or the peer wallet accept/act on terms that don't match what was actually signed off/expected — a concrete loss/dispute vector for funds routed through the arbiter-mediated shared address, satisfying the "private-payment counterparty" fund-loss criterion.

### Likelihood Explanation
Likelihood is currently maximal for any contract created in the present timeframe: because `NEW_HASH_DATE` is set in the future (2026-11-01) relative to the current system date (2026-09-15), 100% of contracts created today use the vulnerable, delimiter-less hash path — this isn't a rare edge case gated by legacy data, it is the default and only path currently reachable via normal contract creation (`createAndSend`). No privileged access is required — a normal peer/counterparty in an arbiter contract negotiation can craft `title`/`text` values to exploit the boundary ambiguity.

### Recommendation
- Immediately apply the delimited encoding (`exports.DELIMITER`) unconditionally, or set `NEW_HASH_DATE` to a date in the past so all contracts (old and new) use the safe branch; retiring the unsafe legacy branch entirely once backward compatibility is no longer needed.
- Prefer a length-prefixed or type-tagged encoding consistent with `string_utils.getSourceString` (which already solves this exact ambiguity class elsewhere in the codebase) instead of ad hoc delimiters, and reject any field containing the delimiter/`\x00` sequence, mirroring the guard in `getSourceString`.
- Audit `prosaic_contract.js`'s `getHashV1`, which has the same delimiter-less concatenation pattern (`contract.title + contract.text + contract.creation_date`) [10](#0-9) , for the same class of issue.

### Proof of Concept
1. Set the system/wallet clock to any date before `2026-11-01` (true today, 2026-09-15).
2. Party A creates an arbiter contract offer via `createAndSend` with `title = "AB"`, `text = "C"`, and fixed `payer_name`, `arbiter_address`, `payee_name`, `amount`, `asset`. `getHashSrc` computes (old branch): `"AB" + "C" + creation_date + payer_name + arbiter_address + payee_name + amount + asset` [4](#0-3) .
3. A malicious counterparty (or Party A themselves, after the fact) constructs an alternate contract object with `title = "A"`, `text = "BC"`, keeping every other field identical.
4. `getHashSrc`/`getHash` produce the exact same concatenated string and therefore the identical SHA-256 `hash` for both contracts [5](#0-4) .
5. Any code path relying on `hash` equality to assert "these are the same agreed contract terms" (e.g. `getByHash`, `respond`, `shareContractToCosigners`) cannot distinguish the two different `title`/`text` pairs, allowing the party controlling which variant is stored/displayed to present different contractual text to different participants (arbiter, cosigners, peer) while the on-record `hash` matches.

### Citations

**File:** arbiter_contract.js (L18-18)
```javascript
exports.NEW_HASH_DATE = '2026-11-01';
```

**File:** arbiter_contract.js (L19-19)
```javascript
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L21-24)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
```

**File:** arbiter_contract.js (L91-155)
```javascript
function store(objContract, bFromCosigner, cb) { // contracts shared by cosigners are trusted to reflect their true status
	const me_is_cosigner = bFromCosigner ? 1 : 0;
	const status = bFromCosigner ? (objContract.status || status_PENDING) : status_PENDING;
	var fields = "(hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, peer_pairing_code, peer_contact_info, my_pairing_code, my_contact_info, me_is_cosigner";
	var placeholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 1, objContract.creation_date, objContract.ttl, status, objContract.title, objContract.text, objContract.peer_pairing_code, objContract.peer_contact_info, objContract.my_pairing_code, objContract.my_contact_info, me_is_cosigner];
	if (bFromCosigner) {
		if (objContract.shared_address) {
			fields += ", shared_address";
			placeholders += ", ?";
			values.push(objContract.shared_address);
		}
		if (objContract.unit) {
			fields += ", unit";
			placeholders += ", ?";
			values.push(objContract.unit);
		}
	}
	fields += ")";
	placeholders += ")";
	db.query("INSERT "+db.getIgnore()+" INTO wallet_arbiter_contracts "+fields+" VALUES "+placeholders, values, function(res) {
		if (cb) {
			cb(res);
		}
	});
}

function respond(hash, status, signedMessageBase64, signer, cb) {
	cb = cb || function(){};
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending" && objContract.status !== "accepted")
			return cb("contract is in non-applicable status");
		var send = function(authors, pairing_code) {
			var response = {hash: objContract.hash, status: status, signed_message: signedMessageBase64, my_contact_info: objContract.my_contact_info};
			if (authors) {
				response.authors = authors;
			}
			if (pairing_code) {
				response.my_pairing_code = pairing_code;
			}
			device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_response", response);

			setField(objContract.hash, "status", status, function(objContract) {
				if (status === "accepted") {
					shareContractToCosigners(objContract.hash);
				};
				cb(null, objContract);
			});
		};
		if (status === "accepted") {
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				setField(objContract.hash, "my_pairing_code", pairing_code);
				composer.composeAuthorsAndMciForAddresses(db, [objContract.my_address], signer, function(err, authors) {
					if (err) {
						return cb(err);
					}
					send(authors, pairing_code);
				});
			});
		} else {
			send();
		}
	});
}
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

**File:** prosaic_contract.js (L102-104)
```javascript
function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```
