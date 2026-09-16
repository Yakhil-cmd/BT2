### Title
Delimiter-injection allows arbitrary hash collision in arbiter contract terms - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` computes a contract's identifying hash by concatenating free-form, attacker/user-controlled text fields (`title`, `text`, party names) with other structured fields (dates, addresses, amount, asset) using a fixed, unescaped delimiter string, then hashing the result. Because the delimiter is a plain substring that can itself appear inside the free-form `title`/`text` fields, the field boundaries used for hashing are not unambiguous — the same root-cause class as ALPINE-CVE-2024-6923 (failure to properly quote/escape a separator character before serializing/joining fields, allowing content to cross field boundaries).

### Finding Description
`getHashSrc()` builds the hash source as: [1](#0-0) 

For contracts created after `NEW_HASH_DATE`, the fields are joined with `exports.DELIMITER = "[|#|]"`: [2](#0-1) 

`title` and `text` are attacker-supplied free text stored and transmitted as-is (no length/character restriction visible in `createAndSend`/`store`), and there is no check anywhere in `arbiter_contract.js` that rejects or escapes occurrences of the literal `DELIMITER` string inside `title`, `text`, or the party-name fields before joining: [3](#0-2) [4](#0-3) 

Compare this to the JSON-based hashing helpers elsewhere in the codebase (`getSourceString` / `getJsonSourceString` in `string_utils.js`), which explicitly detect and reject the join character embedded in string values to keep field boundaries unambiguous: [5](#0-4) 

`getHashSrc` has no equivalent protection: an attacker who controls `title`/`text` (the contract *offeror*, which is any unprivileged wallet user creating an arbiter contract with a peer) can embed the literal sequence `[|#|]` inside those fields. By choosing `title`/`text` content that contains one or more delimiter sequences, it is possible to construct two structurally different contracts (e.g. different `amount`, `asset`, or `payee_address`) whose final joined byte strings — and therefore SHA-256 hashes — are identical, because the receiving/verifying side has no way to tell where `title` ends and `text`, `creation_date`, or the address/amount fields begin.

### Impact Explanation
`contract.hash` is treated throughout the module as a unique, trustworthy identifier binding the agreed contract terms to on-chain enforcement:
- It is embedded directly into the oscript definition of the jointly-controlled shared address as a data-feed key, `"CONTRACT_" + contract.hash`, which gates release of funds based on the arbiter's data-feed post naming that key: [6](#0-5) 
- It is used as the primary lookup key for the contract record (`getByHash`), and is sent to the arbstore server as `contract_text_hash` for dispute/appeal handling: [7](#0-6) 

If two differently-worded/valued contracts can be crafted to collide on the same `hash`, an attacker (as contract offeror) could get a peer, cosigner, or arbstore server to bind or resolve the wrong contract terms under the same `"CONTRACT_"+hash` data-feed key/lookup, since verification of contract identity relies solely on this ambiguous hash rather than on unambiguous field encoding. This can lead to fund release under different terms than the peer accepted (unauthorized fund movement in a private/multisig payment channel), which is the class of impact the scan scope requires (AA/contract fund loss via a reachable path from an unprivileged party in a private-payment chain).

### Likelihood Explanation
The `title` and `text` fields are plain user-supplied strings sent directly from the contract offeror to the peer with no server-side or protocol-side validation rejecting the `[|#|]` delimiter sequence, so exploitation only requires the attacker (any wallet user initiating an arbiter contract) to type/insert that sequence into the contract title or text — no elevated privileges, special network position, or protocol-level access are required, matching the "unprivileged unit/AA/private-payment counterparty" reachability requirement of the scan.

### Recommendation
Do not rely on ambiguous string-join concatenation for the contract identity hash. Replace `getHashSrc`'s delimiter-joined concatenation with a length-prefixed/unambiguous encoding of each field (e.g., reuse `string_utils.getSourceString`/`getJsonSourceString`, which already reject occurrences of the join character inside field values), or explicitly reject/escape occurrences of `exports.DELIMITER` in `title`, `text`, and party-name fields before hashing.

### Proof of Concept
Not fully verified end-to-end (would require exercising `createAndSend`/`getHash` with two crafted contract payloads and confirming identical output hashes, plus tracing the arbstore's use of `contract_text_hash` to confirm it does not independently validate structured fields against the hash) — this was not runnable in this read-only analysis. Conceptually: choose `title = "A" + DELIMITER + "1000000"` and `text = ""` for one contract, and `title = "A"`, `text = "1000000"` for another (with matching `creation_date`, addresses, `arbiter_address`, and `asset`); both serialize via `[contract.title, contract.text, ...].join(DELIMITER)` to the same underlying string and therefore hash identically via `getHash()`, despite `contract.amount`/wording differing between the two logical contracts.

### Citations

**File:** arbiter_contract.js (L19-19)
```javascript
exports.DELIMITER = "[|#|]";
```

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

**File:** arbiter_contract.js (L465-481)
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
					]];
```

**File:** arbiter_contract.js (L597-604)
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
