### Title
Prosaic-contract hash does not bind the contracting parties' addresses, allowing contract-identity collision/duplication - ([File: prosaic_contract.js])

### Summary
`prosaic_contract.js`'s `getHash()` computes the identifying hash of a prosaic (text) contract from only `title + text + creation_date`, while the sibling module `arbiter_contract.js` was already patched (see `exports.NEW_HASH_DATE`) to additionally bind `payer_address`, `payee_address` and `arbiter_address` into its hash source precisely because a hash that omits the parties can be produced/copied by an unrelated pair of addresses. `prosaic_contract.js` still has the unpatched pattern: its commitment hash is not cryptographically tied to `my_address`/`peer_address`, so two structurally identical texts exchanged between different parties collide on the same `hash`.

### Finding Description
`getHash()`/`getHashV1()` in `prosaic_contract.js` are defined as: [1](#0-0) 

Compare this with the already-hardened analog in `arbiter_contract.js`, which explicitly folds in `payer_address`, `payee_address` and `arbiter_address` after `NEW_HASH_DATE` for exactly this reason (to stop identical-text contracts between different parties from sharing a hash): [2](#0-1) 

This `hash` is the sole key used to persist and later look up a contract: [3](#0-2) [4](#0-3) 

It is also the value embedded on-chain as `contract_text_hash` in the "data" message that is used to prove a contract was signed, and the sole content used to validate that a received unit corresponds to *this* contract: [5](#0-4) 

Because `my_address`/`peer_address` are not part of the hash pre-image, any correspondent (an unprivileged device peer, per the "asset issuer / private-payment counterparty / paired device" reachable surface) who learns or predicts a target `title`, `text` and `creation_date` triple can construct their own `prosaic_contract_offer` naming themselves (or an accomplice) as `my_address`/`peer_address`, producing an identical `hash` to a genuine, unrelated contract negotiated by two other parties. Since `hash` is the primary correlation key across `store()`/`getByHash()`/`handleReceivedSigningUnit()`, and the party addresses stored alongside the hash are attacker-controlled input from the network message (not derivable from or checked against the hash itself), this permits contract-identity confusion: an attacker's locally stored `peer_address`/`peer_device_address` can be substituted under the same `hash` that a legitimate on-chain `contract_text_hash` unit refers to, or a genuine `prosaic_contract_offer` can collide with/be shadowed by an attacker's pre-existing row for the same `hash` (the `store()` path even uses `INSERT ... IGNORE`, meaning whichever record was inserted first for a given `hash` silently wins).

This is the same root cause pattern the reference report describes for UMA's DVM: a masked commitment (`hash`) that is not cryptographically bound to the identity of the party making it (nor to other distinguishing context) lets an unrelated party copy or collide with it, defeating the intended non-repudiation/uniqueness of the commitment.

### Impact Explanation
The `hash` is the anchor that ties an off-chain agreed text to an on-chain proof of mutual signing (`payload.contract_text_hash`) and to the locally stored counterparty identity (`peer_address`, `peer_device_address`) used later to derive the shared address that actually escrows/receives funds in the arbiter/prosaic-contract flow. If an attacker can make their own party pairing hash-collide with a legitimate contract, or race the legitimate `store()`/`createAndSend()` insert for a predictable/shared `hash`, the wallet can retain attacker-controlled counterparty/device data under that `hash`, corrupting later flows (dispute matching via `contract_text_hash`, counterparty attribution, shared-address derivation) that assume `hash` uniquely and safely identifies one specific two-party agreement. This can misdirect a party into believing a signed unit that satisfies one contract's hash also proves agreement to a different contract with a different, attacker-substituted counterparty — analogous to how the DVM bug let a copied commitment be misattributed to the wrong voter.

### Likelihood Explanation
Exploitation requires the attacker to know or predict the exact `title`, `text`, and `creation_date` string used by the legitimate parties (creation_date is set with second-level precision by the offering wallet), which is a real but non-trivial precondition — it is most practical when the attacker is one of the two original correspondents (or can observe the offer before it's persisted/answered) and races a duplicate offer, rather than a fully blind third party. This narrows likelihood relative to the original DVM bug (where any bystander could trivially copy public on-chain commitments), but the underlying design flaw — omitting party-address binding from the hash — is identical to the pattern the project's own maintainers already recognized and fixed for `arbiter_contract.js`, strongly suggesting `prosaic_contract.js` was simply missed.

### Recommendation
Update `prosaic_contract.getHash()` (and `getHashV1()`, with a versioned cutover similar to `arbiter_contract.NEW_HASH_DATE`) to include `my_address`, `peer_address` (and ideally `creation_date` is already there, but also consider including any cosigners) in the hash pre-image, mirroring the fix already applied in `arbiter_contract.getHashSrc()`. This ensures the commitment/identifier is cryptographically bound to the specific parties of the agreement and cannot be reproduced or collided with by a different address pairing.

### Proof of Concept
1. Party A and Party B negotiate a prosaic contract with `title=T`, `text=X`, `creation_date=D`; `hash = sha256(T+X+D)` is computed via `getHash()` in [6](#0-5) .
2. An attacker M (aware of, or having observed, `T`, `X`, `D` — e.g., because M is a correspondent who received or intercepted the offer) constructs their own contract object with the same `title`, `text`, `creation_date` but `my_address=M`, `peer_address=C` (a different victim), yielding the identical `hash`.
3. M calls `store()`/`createAndSend()` for their crafted contract, which persists a row keyed by the same `hash` (using `INSERT ... IGNORE` in `store()`), attacker-controlled `peer_address`/`peer_device_address` fields, before or in place of the legitimate A/B record.
4. Subsequent lookups by `hash` (`getByHash()`), or matching of on-chain `contract_text_hash` data messages in `handleReceivedSigningUnit()`, now operate on/against the attacker-substituted party binding rather than the legitimate one, since nothing in the hash itself constrains which addresses are allowed to be associated with it.

### Citations

**File:** prosaic_contract.js (L13-20)
```javascript
function createAndSend(hash, peer_address, peer_device_address, my_address, creation_date, ttl, title, text, cosigners, cb) {
	db.query("INSERT INTO prosaic_contracts (hash, peer_address, peer_device_address, my_address, is_incoming, creation_date, ttl, status, title, text, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [hash, peer_address, peer_device_address, my_address, false, creation_date, ttl, status_PENDING, title, text, JSON.stringify(cosigners)], function() {
		var objContract = {title: title, text: text, creation_date: creation_date, hash: hash, peer_address: my_address, ttl: ttl, my_address: peer_address};
		device.sendMessageToDevice(peer_device_address, "prosaic_contract_offer", objContract);
		if (cb)
			cb(objContract);
	});
}
```

**File:** prosaic_contract.js (L55-70)
```javascript
function store(objContract, cb) {
	var fields = '(hash, peer_address, peer_device_address, my_address, is_incoming, creation_date, ttl, status, title, text';
	var placeholders = '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?';
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, true, objContract.creation_date, objContract.ttl, objContract.status || status_PENDING, objContract.title, objContract.text];
	if (objContract.shared_address) {
		fields += ', shared_address';
		placeholders += ', ?';
		values.push(objContract.shared_address);
	}
	fields += ')';
	placeholders += ')';
	db.query("INSERT "+db.getIgnore()+" INTO prosaic_contracts "+fields+" VALUES "+placeholders, values, function(res) {
		if (cb)
			cb(res);
	});
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
