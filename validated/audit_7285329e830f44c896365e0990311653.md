### Title
Contract Hash Collision via Delimiter Injection in `getHashSrc()` - (File: `arbiter_contract.js`)

### Summary
`arbiter_contract.js` builds the identifying hash of an arbiter contract by naively joining free-text, attacker-controlled fields (`title`, `text`) with a fixed, guessable delimiter string, exactly the bug class described in the external report where a special character embedded in an untrusted value can be used to make a serializer misinterpret field boundaries.

### Finding Description
`getHashSrc()` concatenates the contract's `title`, `text`, `creation_date`, addresses, names, `amount` and `asset` using a plain string delimiter `exports.DELIMITER = "[|#|]"` before hashing: [1](#0-0) 

The delimiter is a short, publicly known constant defined right at module scope: [2](#0-1) 

`title` and `text` are fully attacker-controlled free-text fields supplied by whichever party creates the contract offer (`createAndSend`), and there is no check anywhere in the file that rejects values containing the `DELIMITER` sequence before they are hashed and stored: [3](#0-2) 

Because plain `Array.join()` provides no escaping, an attacker who controls `title`/`text` can embed the literal `"[|#|]"` sequence inside those fields. This shifts the effective field boundaries of the joined string, so two semantically different `(title, text)` pairs can produce the exact same joined source string (and therefore the same SHA-256 hash) as long as the concatenation of `title + DELIMITER + text` is held constant — e.g. `title="A[|#|]B", text="C"` and `title="A", text="B[|#|]C"` hash identically. This is the direct analog of the CVE-2026-0864 class: a value containing a delimiter/control character can inject or shift adjacent "fields" in a naively-serialized text blob.

The resulting `contract.hash` is not a cosmetic value — it is embedded as the arbitration key in the shared-address definition (`"CONTRACT_" + contract.hash` used as a data-feed key that the arbiter posts to release funds): [4](#0-3) 
and it is sent to the arbstore together with a *separately re-encrypted* copy of `title`/`text` when a dispute is opened: [5](#0-4) 

Critically, when a peer or cosigner receives a contract via `arbiter_contract_offer`/`arbiter_contract_shared` and calls `store()`, the code inserts the hash exactly as sent by the remote peer, without recomputing `getHash()` from the received fields to verify integrity: [6](#0-5) 

### Impact Explanation
Because the contract hash is used as the shared-address arbitration key and as the reference passed to the arbstore for dispute resolution, an offeror (a private-payment counterparty reachable without any special privilege) can exploit the delimiter ambiguity to present one version of the contract terms (`title`/`text`) to the counterparty while later submitting a different, colliding `title`/`text` pair under the identical `contract.hash` to the arbstore during `openDispute()`/`appeal()`. Since `store()` never revalidates the hash against the received fields, both parties and the arbstore can end up trusting inconsistent contract content that maps to the same hash/arbitration key, which can be leveraged to bias dispute outcomes and misdirect the release of the shared-address funds (fund loss/freezing for the counterparty).

### Likelihood Explanation
Exploitation requires only that the attacker control the `title`/`text` fields of an arbiter contract they create — a normal, unprivileged capability of any wallet user initiating an arbitration contract. No cryptographic breaking is needed, only careful placement of the fixed 5-character delimiter string inside otherwise free-form text, making this straightforward for a motivated party to craft.

### Recommendation
Reject (or escape) any occurrence of `exports.DELIMITER` inside `title`, `text`, and other user-controlled fields before joining them in `getHashSrc()` (mirroring the null-byte rejection already used in `string_utils.getSourceString`), or switch to a length-prefixed/JSON-based (`getJsonSourceString`) encoding for the hash source so that field boundaries cannot be manipulated by attacker-supplied content. Additionally, `store()` should recompute `getHash()` from the received contract fields and reject the record if it does not match the supplied `hash`.

### Proof of Concept
1. Party A (offeror) crafts `title = "Consulting agreement[|#|]Pay $100"` and `text = "for services"`, and separately crafts `title2 = "Consulting agreement"`, `text2 = "Pay $100[|#|]for services"`.
2. Both `[title, text, ...].join("[|#|]")` and `[title2, text2, ...].join("[|#|]")` produce the identical joined string (`"Consulting agreement[|#|]Pay $100[|#|]for services[|#|]..."`), so `getHash()` in `arbiter_contract.js` (lines 194-207) returns the same SHA-256 hash for both.
3. Party A sends version 1 to the counterparty via `createAndSend`/`arbiter_contract_offer` (lines 21-36), which the counterparty accepts and signs a shared address keyed by `"CONTRACT_" + hash` (lines 465-481).
4. During a later dispute, Party A submits version 2 (with different effective terms) to the arbstore via `openDispute()` (lines 262-319), referencing the same `contract_hash`; the arbstore/arbiter has no way to detect the substitution because both versions hash identically.

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L21-36)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
	device.getOrGeneratePermanentPairingInfo(pairingInfo => {
		objContract.my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
		db.query("INSERT INTO wallet_arbiter_contracts (hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, my_contact_info, my_pairing_code, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 0, objContract.creation_date, objContract.ttl, status_PENDING, objContract.title, objContract.text, objContract.my_contact_info, objContract.my_pairing_code, JSON.stringify(objContract.cosigners) ... (truncated)
				var objContractForPeer = _.cloneDeep(objContract);
				delete objContractForPeer.cosigners;
				device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_offer", objContractForPeer);
				if (cb) {
					cb(objContract);
				}
		});
	});
}
```

**File:** arbiter_contract.js (L91-116)
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

**File:** arbiter_contract.js (L277-296)
```javascript
					var data = {
						contract_hash: hash,
						unit: objContract.unit,
						my_address: objContract.my_address,
						peer_address: objContract.peer_address,
						me_is_payer: objContract.me_is_payer,
						my_pairing_code: objContract.my_pairing_code,
						peer_pairing_code: objContract.peer_pairing_code,
						encrypted_contract: device.createEncryptedPackage({
							title: objContract.title,
							text: objContract.text,
							creation_date: objContract.creation_date,
							plaintiff_party_name: objContract.my_party_name,
							respondent_party_name: objContract.peer_party_name,
							my_contact_info: objContract.my_contact_info,
							peer_contact_info: objContract.peer_contact_info,
						}, objArbiter.device_pub_key),
						my_contact_info: objContract.my_contact_info,
						peer_contact_info: objContract.peer_contact_info
					};
```

**File:** arbiter_contract.js (L474-480)
```javascript
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
```
