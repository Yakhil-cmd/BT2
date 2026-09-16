### Title
Contract-term hash collision via unescaped delimiter in arbiter contract hashing - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` builds the hash that uniquely identifies a private arbiter contract by naively joining user-controlled fields (`title`, `text`, party names, addresses, amount, asset) with a fixed, non-escaped delimiter string. Because none of the joined fields are checked for embedding the delimiter itself, a peer can construct two different sets of contract terms that concatenate to the exact same byte string, and therefore produce the exact same `hash`. This is the same class of bug as the Envoy CVE: values are not sanitized/escaped before being combined into a single canonical string used for a security decision, letting an attacker create ambiguous/"smuggled" content that different consumers interpret differently while a downstream component (the arbiter, the counterparty's shared-address definition) trusts the hash as if it uniquely identified one set of terms.

### Finding Description
`getHashSrc()` computes the source string for the contract hash: [1](#0-0) 

using the fixed delimiter: [2](#0-1) 

`title`, `text`, `my_party_name`, and `peer_party_name` are free-form strings supplied by the wallet users (private-payment counterparties) when creating/accepting a contract via `createAndSend()`/`store()`, and are never checked for containing the literal delimiter `"[|#|]"`: [3](#0-2) [4](#0-3) 

Because `Array.prototype.join` performs no escaping, two different field decompositions can serialize to an identical string:
- Set 1: `title = "A[|#|]B"`, `text = "C"`
- Set 2: `title = "A"`, `text = "B[|#|]C"`

Both produce the identical joined string `"A[|#|]B[|#|]C[|#|]..."` and therefore `getHash()` returns the same SHA-256 hash: [5](#0-4) 

This is structurally the same root cause as the reported Envoy bug: an unescaped separator character allows attacker-controlled content to "leak" across field boundaries, producing two semantically different messages that are indistinguishable to a component that only checks a canonical/serialized representation (here, the contract `hash`).

The `hash` is not just a display artifact — it is embedded directly in the on-chain address definition that locks/releases the payment for the contract, via `"CONTRACT_" + contract.hash` used as the data-feed key checked by the counterparty's shared multisig address: [6](#0-5) 
and is separately forwarded to the arbiter/arbstore for dispute resolution (`contract_hash`), together with a re-serialized `encrypted_contract` payload built independently from the same ambiguous fields: [7](#0-6) 

Notably, the project already recognizes exactly this class of bug and defends against it elsewhere: `string_utils.getSourceString()` (used for unit/joint hashing) explicitly rejects any string or object key containing its join character before concatenating: [8](#0-7) 
and the data-feed subsystem explicitly rejects `\n` in feed names/values for the same reason: [9](#0-8) 
`arbiter_contract.js`'s newer (`creation_date > NEW_HASH_DATE`) hashing scheme was not given the same protection.

### Impact Explanation
A malicious contract counterparty (a "private-payment counterparty" — squarely in scope) can present one set of contract terms (title/text describing the deal) to the honest party for review/acceptance while being able to construct an alternate, differently-worded (or differently-scoped) set of terms that hashes to the identical value. Since the contract `hash` is what:
1. Gets embedded in the on-chain oracle condition (`"CONTRACT_"+hash`) governing release of the escrowed funds from the shared address, and
2. Is the identifier sent to the arbiter/arbstore to adjudicate a dispute,

the attacker can exploit the collision to have the arbiter (or the victim) operate on a different textual agreement than the one actually reviewed/approved, while all hash-based integrity checks pass. In a dispute, this can be leveraged to steer the arbiter's decision or to repudiate/alter agreed terms, resulting in the honest party's escrowed funds being released to the attacker — i.e., fund loss for the honest counterparty in a payment secured by ocore's arbiter-contract feature.

### Likelihood Explanation
Exploitation requires no special privileges beyond being a normal wallet user negotiating an arbiter contract with a victim — a role explicitly in scope ("private-payment counterparty"). Constructing the colliding strings is trivial (pure string manipulation, no cryptographic effort), and the attacker fully controls `title`/`text`/party names on their side of the negotiation. The only constraint is convincing the victim to accept a contract whose title/text is worded so that shifting the delimiter still reads plausibly under both splits, which is a social/wording constraint rather than a technical one.

### Recommendation
Reject (or escape) any occurrence of `exports.DELIMITER` inside `title`, `text`, `my_party_name`, `peer_party_name`, or any other field passed into `getHashSrc()`, mirroring the approach already used in `string_utils.getSourceString()` (reject the join character) and in `validation.js`'s data-feed checks (reject `\n`). Alternatively, switch to a length-prefixed or JSON-based canonical encoding (e.g., `getJsonSourceString`-style hashing) so field boundaries cannot be manipulated by content.

### Proof of Concept
```js
const arbiter_contract = require('./arbiter_contract.js');

const base = {
  me_is_payer: true,
  creation_date: '2027-01-01 00:00:00', // > NEW_HASH_DATE, uses DELIMITER branch
  my_address: 'PAYER_ADDR',
  peer_address: 'PAYEE_ADDR',
  arbiter_address: 'ARBITER_ADDR',
  amount: 1000,
  asset: null,
};

const contractA = { ...base, title: 'A[|#|]B', text: 'C', my_party_name: '', peer_party_name: '' };
const contractB = { ...base, title: 'A', text: 'B[|#|]C', my_party_name: '', peer_party_name: '' };

console.log(arbiter_contract.getHashSrc(contractA) === arbiter_contract.getHashSrc(contractB)); // true
console.log(arbiter_contract.getHash(contractA) === arbiter_contract.getHash(contractB));       // true, despite different title/text
```

Note: I was able to confirm this via source inspection of the exact join logic and delimiter constant, but did not execute the code in a live environment (no filesystem/terminal access in this mode); the collision follows directly and deterministically from `Array.prototype.join` semantics shown in `getHashSrc`.

### Citations

**File:** arbiter_contract.js (L17-19)
```javascript
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

**File:** arbiter_contract.js (L205-207)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
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

**File:** arbiter_contract.js (L473-480)
```javascript
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
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

**File:** validation.js (L1933-1943)
```javascript
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
```
