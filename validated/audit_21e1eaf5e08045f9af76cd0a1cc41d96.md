### Title
Attacker-controlled `creation_date` permanently bypasses the delimiter-safe arbiter contract hash, re-enabling hash-collision via field-boundary shifting - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` gates the arbiter-contract hashing algorithm on a hardcoded absolute date constant, `NEW_HASH_DATE`, compared against the contract's own `creation_date` field. Because `creation_date` is attacker-supplied (set locally by whichever peer initiates the contract) and never validated against real wall-clock time, a malicious counterparty can always force the vulnerable legacy hashing branch, regardless of the actual date, defeating the delimiter/address-inclusion fix that the hardcoded date was meant to permanently activate.

### Finding Description
`exports.NEW_HASH_DATE = '2026-11-01'` is a hardcoded, immutable date constant: [1](#0-0) 

It is used in `getHashSrc()` to select between two hashing algorithms for an arbiter contract: [2](#0-1) 

- The "new" branch (`creation_date > NEW_HASH_DATE`) includes `payer_address`, `arbiter_address`, `payee_address` and joins the fields with a distinct delimiter, `exports.DELIMITER = "[|#|]"`.
- The "old"/legacy branch joins the same class of fields with `.join("")` — **no delimiter at all** — and omits the payer/payee addresses entirely, relying only on party names.

Concatenating variable-length untrusted strings (`title`, `text`, party names) with no delimiter is a classic hash-canonicalization flaw: different combinations of `title`/`text`/`party_name` boundaries can produce an identical concatenated string and therefore an identical SHA-256 hash. The `NEW_HASH_DATE` constant and the added `DELIMITER`/addresses were evidently introduced specifically to close this hole going forward.

The critical defect is that the branch selector, `contract.creation_date`, is not derived from any trusted/consensus timestamp — it is set client-side by the initiating peer at contract creation: [3](#0-2) 

and persisted verbatim from whatever the counterparty sends, with no bound/sanity check against local time, when a contract offer or shared-contract message is stored: [4](#0-3) 

Since a malicious party fully controls the `creation_date` string it embeds in an arbiter contract offer, it can simply set `creation_date` to any date earlier than `2026-11-01` (e.g., `"2020-01-01 00:00:00"`) no matter when the contract is actually created. This deterministically routes `getHashSrc()`/`getHash()` into the legacy, delimiter-less, address-free branch for that contract, on both the offering and any verifying party's client, because both compute the hash identically from the same (attacker-chosen) `creation_date` field. The hardcoded cutover date can therefore never actually retire the vulnerable code path for an adversarial counterparty — exactly the same class of bug as `INFLATION_PROTECTION_TIME` in the referenced report: a fixed, non-enforced timestamp intended to gate security-relevant behavior for "all time going forward," but trivially rendered ineffective because the comparison input is not tied to any tamper-proof clock.

### Impact Explanation
The arbiter-contract hash (`contract.hash`) is the sole identifier used to bind the off-chain contract text/terms to the on-chain escrow: it is embedded in the `data` message payload (`contract_text_hash`) that both parties sign, and it is used as the data-feed key (`"CONTRACT_" + contract.hash`) that the arbiter uses to declare a winner and unlock the shared/multisig address funds. If a malicious counterparty can produce a colliding hash for two different sets of `title`/`text`/party names, they can present one contract to the arbiter/dispute process while having originally agreed a different (less favorable, to the victim) contract that hashes identically, or otherwise manipulate which terms are treated as authoritative for the escrow's fund release. This is a direct fund-loss/fraud vector against private-payment/arbiter-contract counterparties reachable purely through paired-device contract-message handling — no privileged access required.

### Likelihood Explanation
Any counterparty in an arbiter contract negotiation controls the `creation_date` field they send; nothing in `store()`, `getByHash()`, or the contract offer/response flow re-derives or validates `creation_date` from a trusted source. Forcing the legacy branch requires only choosing a `creation_date` string lexicographically before `'2026-11-01'`, which is trivial and requires no special timing, network position, or privileged role — only that the attacker is one of the two contracting parties (a normal, expected actor in this feature).

### Recommendation
- Do not gate hash-algorithm selection on a user-supplied field (`creation_date`); if a hash-format migration is needed, use a single canonical/fixed algorithm rather than a self-declared date, or bind the cutover to a trusted, externally-verifiable source (and re-validate `creation_date` server/hub-side as "not before now / not obviously backdated").
- Remove the legacy delimiter-less branch entirely (or reject contracts whose declared `creation_date` triggers it) so the vulnerable concatenation path can no longer be selected.
- Always include the payer/payee addresses and use the safe delimiter in the hash input, unconditionally.

### Proof of Concept
1. Attacker (peer A) prepares an arbiter contract offer with `creation_date` deliberately set to `"2000-01-01 00:00:00"` (bypassing `Date.now()`), and crafts `title`/`text`/`peer_party_name` such that concatenating `[title, text, creation_date, payer_name, arbiter_address, payee_name, amount, asset]` with no delimiter produces the same byte string as an alternate, more attacker-favorable set of `title`/`text`/party-name values.
2. `getHashSrc()` takes the legacy branch because `"2000-01-01 00:00:00" > "2026-11-01"` is false, joining fields via `.join("")`: [5](#0-4) 
3. The resulting `contract.hash` is identical for both the "agreed" contract and the attacker's colliding alternate contract.
4. Victim (peer B) signs based on the terms they believe correspond to `contract.hash`; the attacker can later present the colliding alternate contract text to the arbiter for dispute resolution, since the on-chain `contract_text_hash` / `CONTRACT_<hash>` data-feed key cannot distinguish the two.

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
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
