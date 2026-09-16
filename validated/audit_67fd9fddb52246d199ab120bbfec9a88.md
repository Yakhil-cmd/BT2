### Title
Arbiter Contract Hash Uses Unescaped Field Concatenation, Allowing Forgery of Contract Terms Under an Identical Hash - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js`'s `getHashSrc()` builds the canonical identifier (`hash`) of a peer-to-peer arbiter contract by concatenating free-text, peer-controlled fields (`title`, `text`, `my_party_name`/`peer_party_name`) either with no separator at all (legacy path) or with a fixed, non-escaped delimiter (`"[|#|]"`, new path). Because the delimiter/boundary between adjacent free-text fields is never escaped inside the field values themselves, a peer can craft two semantically different contracts whose `getHashSrc()` output — and therefore `hash` — is byte-for-byte identical. This is the same root-cause class as CVE-2021-27099: an identity/ID-building "template" inserts attacker-controlled values into fixed positions without normalizing the delimiter that separates them, letting the attacker relocate the boundary and forge a different logical identity while keeping the same nominal identifier. [1](#0-0) 

### Finding Description
`getHashSrc()`:
```
const src = contract.creation_date > exports.NEW_HASH_DATE
     ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
     : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
``` [2](#0-1) 

`exports.NEW_HASH_DATE = '2026-11-01'` [3](#0-2)  — since the environment date is 2026-09-15, every contract created today still uses the legacy branch, which joins `title`, `text` and other free-text fields with the **empty string**. `title` and `text` are directly adjacent, attacker-controlled, unbounded-length strings, so any suffix of `text` can be moved into `title` (or vice versa) without changing the concatenated byte stream, and thus without changing `hash` = `sha256(getHashSrc(contract))` [4](#0-3) .

Even in the "fixed" branch that adds `DELIMITER = "[|#|]"`, the delimiter itself is never stripped/escaped from field content. An attacker who deliberately embeds the literal `"[|#|]"` sequence inside `text` can still relocate the title/text boundary and produce a second, different `(title, text)` pair that serializes to the identical string and hash. The same lack of escaping applies to `getContactsHash()`, which joins pairing codes/contact info with `"|"` [5](#0-4) .

This `hash` is the sole content identifier trusted throughout the protocol:
- It is the primary key of `wallet_arbiter_contracts` and is embedded on-chain as `contract_text_hash` in the `data` message posted when the shared address is funded [6](#0-5) .
- Receipt-side verification (`handleReceivedSigningUnit`) only checks that `payload.contract_text_hash === contract.hash`; it never re-derives/validates that the locally-known `title`/`text` actually hash to that value [7](#0-6) .
- During a dispute, the *encrypted* `title`/`text`/party names are sent to the external arbiter/ArbStore, tied only by `contract_hash` [8](#0-7) . The arbiter never independently reconstructs `hash` from those fields to confirm they weren't swapped/split.

Because the boundary between `title` and `text` (and similarly other adjacent free-text fields) is not cryptographically bound, a dishonest party in a bilateral arbiter contract (a "private-payment counterparty") can present one rendering of contract terms to the counterparty at negotiation time, then submit a different split of the same underlying bytes (which can materially change what is *displayed*, since title/text are typically rendered differently, e.g. bold heading vs. body) to the arbiter or to logs, while both remain provably tied to the very same `hash`/on-chain `contract_text_hash`.

### Impact Explanation
The contract `hash` is meant to be an immutable, verifiable commitment to the exact negotiated terms (title, text, parties, amount, asset, arbiter). The unescaped concatenation breaks this guarantee: an attacker-controlled peer can produce two different apparent contracts that are indistinguishable at the cryptographic-commitment layer. This can be leveraged to mislead the counterparty or the arbiter about the true terms of the deal during a dispute (`openDispute`/`appeal`), which decides who receives the escrowed funds from the shared address. Since dispute outcomes directly control release of already-deposited funds (`complete()` pays either the peer or refunds the payer based on the arbiter's ruling) [9](#0-8) , a successful terms-forgery can result in funds being awarded based on misrepresented contract text — i.e., unauthorized diversion of escrowed value. This is a Medium-severity integrity/authenticity flaw in a private-payment feature reachable by any counterparty in an arbiter-mediated deal.

### Likelihood Explanation
Exploitation requires only that one of the two contracting peers behaves maliciously — no special privileges, node compromise, or network position are needed. Crafting a colliding `(title, text)` split is trivial arithmetic (move N characters across the boundary, or embed the literal delimiter once the "fixed" hashing scheme takes effect on 2026-11-01). The bug is reachable purely through the standard `createAndSend`/`respond` device-message flow between paired wallets negotiating an arbiter contract.

### Recommendation
- Derive the contract hash from a length-prefixed or otherwise unambiguous encoding of each field (e.g., hash each field separately then hash the concatenation of fixed-length digests, or JSON-encode with a canonical serializer) instead of naive string concatenation/joining with a delimiter that can appear inside user-controlled fields.
- Reject or escape any occurrence of the chosen delimiter within `title`, `text`, `my_party_name`, `peer_party_name`, contact info, and pairing codes before hashing.
- Apply the fix retroactively (or move `NEW_HASH_DATE` to the past) so the vulnerable empty-join scheme is not used for any currently created contracts.
- Have the arbiter/ArbStore side re-derive and check the contract hash from the received `title`/`text`/party fields rather than trusting the caller-supplied `contract_hash` value alone.

### Proof of Concept
1. Peer A proposes an arbiter contract with `title = "Pay 100 for goods, "`, `text = "no refunds"`.
2. `getHashSrc` (legacy branch, active until 2026-11-01) concatenates with `""`, producing `...Pay 100 for goods, no refunds...`. `hash = sha256(that string)`.
3. Peer A later (e.g., when opening a dispute) submits an alternate split with the identical byte stream: `title = "Pay 100 for goods, no refunds"`, `text = ""`. `getHashSrc` produces the exact same concatenated string and therefore the same `hash`, satisfying `payload.contract_text_hash === contract.hash` checks and the arbiter's hash-based lookup, even though the two renderings can be displayed very differently to a human reviewer (e.g., splitting so that a materially different phrase ends up as the bolded "title").
4. The arbiter, evaluating disputed terms based on the submitted `title`/`text` split rather than a canonical, escape-safe encoding, can be misled into ruling based on the attacker's chosen presentation while both parties/hash validators still see a matching `contract.hash`.

### Citations

**File:** arbiter_contract.js (L18-18)
```javascript
exports.NEW_HASH_DATE = '2026-11-01';
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

**File:** arbiter_contract.js (L209-216)
```javascript
function getContactsHash(contract) {
	const payer_pairing_code = contract.me_is_payer ? contract.my_pairing_code : contract.peer_pairing_code;
	const payee_pairing_code = contract.me_is_payer ? contract.peer_pairing_code : contract.my_pairing_code;
	const payer_contact_info = contract.me_is_payer ? contract.my_contact_info : contract.peer_contact_info;
	const payee_contact_info = contract.me_is_payer ? contract.peer_contact_info : contract.my_contact_info;
	const src = [payer_contact_info || '', payer_pairing_code || '', payee_contact_info || '', payee_pairing_code || ''].join("|");
	return crypto.createHash("sha256").update(src, "utf8").digest("base64");
}
```

**File:** arbiter_contract.js (L277-303)
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
					db.query("SELECT 1 FROM assets WHERE unit IN(?) AND is_private=1 LIMIT 1", [objContract.asset], function(rows){
						if (rows.length > 0) {
							data.asset = objContract.asset;
							data.amount = objContract.amount;
						}
						var dataJSON = JSON.stringify(data);
						httpRequest(url, "/api/dispute/new", dataJSON, function(err, resp) {
```

**File:** arbiter_contract.js (L596-604)
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

**File:** arbiter_contract.js (L673-677)
```javascript
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
		const author = objUnit.authors.find(author => author.address === contract.shared_address);
```

**File:** arbiter_contract.js (L719-796)
```javascript
function complete(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, async function(objContract) {
		if (objContract.status !== "paid" && objContract.status !== "in_dispute")
			return cb("contract can't be completed");
		const err = await fillArbstoreAddresses(objContract);
		if (err)
			return cb(err);
		storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
			var opts;
			new Promise((resolve, reject) => {
				if (assetInfo && assetInfo.is_private) {
					var value = {};
					value["CONTRACT_DONE_" + objContract.hash] = objContract.peer_address;
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.my_address],
						signing_addresses: [objContract.my_address],
						change_address: objContract.my_address,
						messages: [{
							app: 'data_feed',
							payload_location: "inline",
							payload_hash: objectHash.getBase64Hash(value, true),
							payload: value
						}]
					};
					resolve();
				} else {
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.shared_address],
						change_address: objContract.shared_address,
						asset: objContract.asset
					};
					if (objContract.me_is_payer && !(assetInfo && (assetInfo.fixed_denominations || assetInfo.is_private))) { // complete
						require("./wallet_defined_by_addresses.js").readSharedAddressDefinition(objContract.shared_address, function (arrDefinition) {
							const index = objContract.is_incoming ? 2 : 1;
							const peer_amount = arrDefinition[1][index][1][1][1].amount;
							const arbstore_amount = arrDefinition[1][index][1][2] && arrDefinition[1][index][1][2][0] === 'has' ? arrDefinition[1][index][1][2][1].amount : 0;
							if (!isFinite(peer_amount) || !isFinite(arbstore_amount))
								throw new Error("invalid amounts in shared address definition: " + JSON.stringify(arrDefinition));
							if (peer_amount + arbstore_amount !== objContract.amount)
								throw new Error(`amounts in shared address definition do not sum up to contract amount: ${peer_amount} + ${arbstore_amount} !== ${objContract.amount}`);
							if (arbstore_amount > peer_amount)
								throw new Error(`arbstore cut is more than 50% of the total amount, peer_amount: ${peer_amount}, arbstore_amount: ${arbstore_amount}`);
							if (arbstore_amount === 0) {
								opts.to_address = objContract.peer_address;
								opts.amount = objContract.amount;
							} else {
								opts[objContract.asset && objContract.asset != "base" ? "asset_outputs" : "base_outputs"] = [
									{ address: objContract.peer_address, amount: peer_amount},
									{ address: objContract.arbstore_address, amount: arbstore_amount},
								];
							}
							resolve();
						});
					} else { // refund
						opts.to_address = objContract.peer_address;
						opts.amount = objContract.amount;
						resolve();
					}
				}
			}).then(() => {
				if (arrSigningDeviceAddresses.length)
					opts.arrSigningDeviceAddresses = arrSigningDeviceAddresses;
				walletInstance.sendMultiPayment(opts, function(err, unit){
					if (err)
						return cb(err);
					var status = objContract.me_is_payer ? "completed" : "cancelled";
					setField(objContract.hash, "status", status, function(objContract){
						cb(null, objContract, unit);
					});
				});
			}).catch(err => {
				cb(err);
			});
		});
	});
}
```
