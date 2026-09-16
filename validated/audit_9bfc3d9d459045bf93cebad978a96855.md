### Title
Delimiter-injection in arbiter-contract hash construction enables hash/data-feed-key collision and unauthorized escrow release - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js` builds the identifying hash of a peer-to-peer escrow ("arbiter") contract by naively joining untrusted, attacker-controlled `title`/`text` strings with a fixed delimiter and hashing the result, without ever checking that the delimiter cannot occur inside those fields. This mirrors the CVE-2022-1271 bug class: a fixed separator character is used to compose several data fields into one string, and because occurrences of the separator inside an untrusted field are never rejected, different field breakdowns can be crafted to produce byte-identical composed strings (and therefore identical hashes/keys) even though the semantic content differs.

### Finding Description
`getHashSrc()` computes the contract hash by joining title/text/creation_date/addresses/amount/asset with `exports.DELIMITER = "[|#|]"`: [1](#0-0) 

Neither `title` nor `text` (both fully attacker-controlled, free-form strings entered by the contract-creating peer in `createAndSend`) are checked for containing the literal delimiter substring `"[|#|]"`: [2](#0-1) 

Because `Array.prototype.join` performs no escaping, if `text` already contains the delimiter, the exact same concatenated string — and therefore the exact same SHA-256 hash — can be produced by two different `(title, text)` pairs, e.g. `(title, "A[|#|]B")` and `(title+"[|#|]A", "B")` both serialize to `title + "[|#|]A[|#|]B"`.

This hash is not merely a display artifact — it is embedded as a discriminator in the on-chain escrow condition. `deriveSharedAddress()` builds the multisig/escrow address definition using `"CONTRACT_" + contract.hash` as the data-feed key that the arbiter posts to resolve a dispute: [3](#0-2) 

Since the arbiter resolves a dispute by posting a `data_feed` unit with key `CONTRACT_<hash>` and value = winner address, and this key is looked up generically by `"in data feed"` in the address definition, any second contract (same arbiter, same payer/payee addresses/amount/asset) whose `getHash()` collides with the first will have an address definition containing the identical `"in data feed", [[arbiter_address], "CONTRACT_"+hash, ...]` branch, so the arbiter's single resolution unit for contract A also satisfies the release condition for contract B's shared address.

### Impact Explanation
An attacker who is a counterparty in two escrow deals that share the same arbiter, payer/payee addresses, amount and asset (all attacker-controlled at contract-creation time) can force both contracts to compute the same `getHash()` by embedding the delimiter inside the `text` of one contract. Both shared escrow addresses then contain an identical `"CONTRACT_<hash>"` data-feed release condition. When the arbiter genuinely resolves the dispute for one contract, that single arbiter data-feed unit also satisfies the release branch of the other (unrelated) contract's shared address, releasing its escrowed funds to whichever address the crafted collision points to — without the arbiter ever reviewing that second dispute. This is a concrete unauthorized release of escrowed funds (private or public asset), matching the "unauthorized spending" impact bar.

### Likelihood Explanation
The delimiter (`"[|#|]"`) is unlikely to appear in legitimate text by accident, but is trivially insertable by a malicious contract-creating peer since `title`/`text` are free-form. Exploitation additionally requires the two colliding contracts to share `arbiter_address`, `payer_address`, `payer_name`, `arbiter_address`, `payee_address`, `payee_name`, `amount`, `asset`, and `creation_date` (second-resolution timestamp) — feasible for a single attacker orchestrating two contracts (e.g. scripted creation within the same second, or exploiting the legacy pre-`NEW_HASH_DATE` branch which uses no delimiter at all and is therefore even easier to collide). Note the code even has a `NEW_HASH_DATE`/`DELIMITER` mechanism that appears to be an incomplete attempt to harden the original no-delimiter concatenation, confirming the maintainers were already aware collision was a concern but did not add validation to reject the delimiter inside `title`/`text`.

### Recommendation
- Reject (or escape) any occurrence of `exports.DELIMITER` inside `title`, `text`, and other joined fields before computing `getHashSrc()`, analogous to the explicit `indexOf('\n')` checks already used for data-feed names/values elsewhere in the codebase (see `validation.js` lines 1936/1942).
- Prefer a length-prefixed or JSON-based (`string_utils.getJsonSourceString`/`getSourceString`) canonical serialization for `getHashSrc`, consistent with how the rest of ocore hashes structured objects, instead of naive string concatenation with a guessable separator.

### Proof of Concept
```js
const arbiterContract = require('./arbiter_contract.js');

const base = {
  me_is_payer: true,
  my_address: 'PAYER_ADDR...',
  peer_address: 'PAYEE_ADDR...',
  my_party_name: 'Alice',
  peer_party_name: 'Bob',
  arbiter_address: 'ARBITER_ADDR...',
  amount: 1000,
  asset: null,
  creation_date: '2026-12-01 12:00:00',
};

// Contract A: attacker embeds the delimiter inside text
const contractA = { ...base, title: 'Deal', text: 'ClauseX[|#|]ClauseY' };

// Contract B: same total string, different title/text split
const contractB = { ...base, title: 'Deal[|#|]ClauseX', text: 'ClauseY' };

console.log(arbiterContract.getHashSrc(contractA) === arbiterContract.getHashSrc(contractB)); // true
```
Both contracts, despite showing different `title`/`text` to their respective counterparties, generate the identical `contract.hash`, and therefore the identical `"CONTRACT_"+hash` data-feed key used in the escrow release condition built by `deriveSharedAddress`.

### Citations

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

**File:** arbiter_contract.js (L454-481)
```javascript
function deriveSharedAddress(hash, bOfferor, cb) {
	getByHash(hash, function (contract) {
		const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
		const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
		const offeror_is_payer = bOfferor ? contract.me_is_payer : !contract.me_is_payer;
		const offeror_device_address = bOfferor ? device.getMyDeviceAddress() : contract.peer_device_address;
		const acceptor_device_address = bOfferor ? contract.peer_device_address : device.getMyDeviceAddress();
		arbiters.getArbstoreInfo(contract.arbiter_address, function(err, arbstoreInfo) {
			if (err)
				return cb(err);
			storage.readAssetInfo(db, contract.asset, function (assetInfo) {
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
