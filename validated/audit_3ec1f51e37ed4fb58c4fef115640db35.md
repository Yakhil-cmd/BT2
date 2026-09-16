Confirmed: `getHashSrc` (arbiter_contract.js:194-203), which is the value both parties cryptographically commit to via `getHash()` when proposing/accepting a contract, includes only `contract.amount` (the gross amount) — it never includes the ArbStore's `cut`. The actual payout split embedded in the on-chain shared-address definition is computed later, independently by each side, in `deriveSharedAddress()` using a `cut` value fetched live from the ArbStore over HTTP via `arbiters.getArbstoreInfo()`.

### Title
ArbStore can silently change its cut after contract agreement, reducing the payee's committed payout - (File: arbiter_contract.js)

### Summary
In the peer-to-peer arbiter-contract flow, the two counterparties cryptographically commit to contract terms via `getHash()`/`getHashSrc()`, which only covers `amount`, `asset`, addresses, and text — never the ArbStore's revenue `cut`. The actual on-chain payout split (`peer_amount` vs `arbstore_amount`) is computed later and independently by each party in `deriveSharedAddress()` using `arbstoreInfo.cut`, fetched live from the ArbStore's HTTP endpoint at the moment the shared address is derived, not at the moment the contract terms were agreed upon.

### Finding Description
`getHashSrc` [1](#0-0)  defines exactly what is bound by the mutually-signed contract hash — `title`, `text`, `creation_date`, addresses/names, `amount`, and `asset`. The `cut` is absent.

The payout amounts actually embedded in the on-chain smart-contract (shared address) definition are computed in `deriveSharedAddress`, which calls `arbiters.getArbstoreInfo(contract.arbiter_address, ...)` to obtain `arbstoreInfo.cut` and then derives `peer_amount = amount * (1 - cut)` and `arbstore_amount = amount - peer_amount` [2](#0-1) . This happens both when the offeror creates the shared address (`createSharedAddressAndPostUnit` → `deriveSharedAddress(hash, true, ...)`) and independently when the acceptor verifies it (`handleReceivedSharedAddress` → `deriveSharedAddress(hash, false, ...)`) [3](#0-2) .

`getArbstoreInfo` fetches `cut` fresh from the ArbStore's own HTTP `/api/get_info` endpoint and only bounds it to `0 <= cut < 1`; it does not pin/commit the value at proposal time and only caches it per-process in `arbStoreInfos[arbiter_address]` [4](#0-3) .

Because `cut` is outside the signed/committed contract terms, the ArbStore operator can change the published `cut` for an arbiter address between the moment the peer agrees to the deal (based on the gross `amount` they were shown) and the moment the shared address is actually derived/created and paid into. Since both sides simply re-derive the definition with whatever `cut` is currently published and check that the resulting address hash matches, a changed `cut` doesn't cause the transaction to be rejected — it just silently produces a different, mutually-"matching" split that gives the payee less (or the ArbStore more) than what was implicitly agreed when the deal was struck, entirely outside of the on-chain unit-validation/DAG-consensus layer that would otherwise guarantee terms are immutable once committed.

### Impact Explanation
The payee (`peer_address`) can receive a smaller payout than the gross `amount` they accepted, with the difference silently redirected to the ArbStore address, without any additional signature or on-chain commitment from the payee acknowledging the changed split. This is a fund-value-altering unilateral parameter change made by one contractual party (the ArbStore/arbiter service) that neither the payer nor payee explicitly re-consented to — the exact bug class described in the report (a privileged counterparty changing an unbounded/uncommitted parameter that directly determines fund distribution after the other party has already committed to the deal).

### Likelihood Explanation
This requires the ArbStore operator (a role structurally similar to the "pool lender" in the report — a semi-trusted counterparty who controls a parameter relied upon by the borrower/payee but who is not one of the two contracting device users) to change its published `cut` between contract acceptance and shared-address creation/verification, which is entirely under that operator's own control and requires no special timing/network conditions — it is a normal HTTP response value it can change at will at any time.

### Recommendation
Bind the ArbStore `cut` (or the fully-resolved `peer_amount`/`arbstore_amount`) into the contract's committed hash (`getHashSrc`) at proposal/acceptance time, so both parties cryptographically agree to the exact split before any shared address is derived. `deriveSharedAddress` should use the `cut` value recorded on the contract at acceptance time rather than re-fetching a live value from the ArbStore, and should fail/warn if the currently-published `cut` differs from the one committed to in the contract.

### Proof of Concept
1. Alice (offeror/payer) and Bob (acceptor/payee) negotiate an arbiter contract for `amount = 1000` via `createAndSend`/`respond("accepted")`; both compute `getHash()` over `amount=1000` — `cut` is not part of this hash [5](#0-4) .
2. At the time of negotiation, the ArbStore publishes `cut = 0.02` for the chosen arbiter address (via `/api/get_info`).
3. Before Alice calls `createSharedAddressAndPostUnit` (which triggers `deriveSharedAddress` → `arbiters.getArbstoreInfo`), the ArbStore operator changes its published `cut` to `0.20`.
4. `deriveSharedAddress` computes `peer_amount = Math.floor(1000 * (1 - 0.20)) = 800` and `arbstore_amount = 200`, embedding this split into the shared-address definition [6](#0-5) .
5. Bob's device independently calls `deriveSharedAddress(hash, false, ...)` in `handleReceivedSharedAddress`, fetches the same now-changed `cut = 0.20` from the ArbStore, computes the identical (now unfavorable) definition, and the hash check passes [7](#0-6) , so Bob's client accepts the shared address without any indication that the split differs from what was implicitly assumed at negotiation time.
6. When the contract completes, Bob receives `800` instead of the `980` he would have gotten under the originally-published `2%` cut, with the extra `180` going to the ArbStore — entirely outside of anything either device user explicitly signed off on.

Note: this analysis is based on the arbiter-contract wallet-side logic (`arbiter_contract.js`, `arbiters.js`); I was not able to inspect the ArbStore server-side implementation (external service, not part of this repo) to confirm whether it enforces any additional commitment of `cut` at deal time, so real-world exploitability depends on that external component's behavior.

### Citations

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

**File:** arbiter_contract.js (L461-522)
```javascript
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
				var isPrivate = assetInfo && assetInfo.is_private;
				var isFixedDen = assetInfo && assetInfo.fixed_denominations;
				var hasArbStoreCut = arbstoreInfo.cut > 0;
				if (isPrivate) { // private asset
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["in data feed", [[acceptor_address], "CONTRACT_DONE_" + contract.hash, "=", offeror_address]]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["in data feed", [[offeror_address], "CONTRACT_DONE_" + contract.hash, "=", acceptor_address]]
					]];
				} else {
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
							address: acceptor_address
						}]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer || isFixedDen || !hasArbStoreCut ? contract.amount : Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
							address: offeror_address
						}]
					]];
					if (!isFixedDen && hasArbStoreCut) {
						arrDefinition[1][offeror_is_payer ? 1 : 2][1].push(
							["has", {
								what: "output",
								asset: contract.asset || "base",
								amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
								address: arbstoreInfo.address
							}]
						);
					}
```

**File:** arbiter_contract.js (L632-657)
```javascript
function handleReceivedSharedAddress(hash, shared_address, from_cosigner, retry_count = 0) {
	console.log(`received shared address ${shared_address} for arbiter contract ${hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
				return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
			}
			const expected_shared_address = objectHash.getChash160(arrDefinition);
			if (expected_shared_address !== shared_address)
				return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
			console.log(`shared address ${expected_shared_address} matches the received one, setting it to the contract and sharing with cosigners`);
			setField(hash, "shared_address", shared_address, function (contract) {
				eventBus.emit("arbiter_contract_update", contract, "shared_address", shared_address);
			}, from_cosigner);
		});
	});
```

**File:** arbiters.js (L51-80)
```javascript
function getArbstoreInfo(arbiter_address, cb) {
	if (!cb)
		return new Promise(function(resolve, reject){
			getArbstoreInfo(arbiter_address, function(err, info){
				if (err) return reject(err);
				resolve(info);
			});
		});
	if (arbStoreInfos[arbiter_address]) return cb(null, arbStoreInfos[arbiter_address]);
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err) {
			return cb(err);
		}
		if (!validationUtils.isNonemptyString(url))
			return cb("invalid url received from hub");
		requestInfoFromArbStore(url+'/api/get_info', function(err, info){
			if (err)
				return cb(err);
			if (!validationUtils.isNonemptyObject(info))
				return cb("invalid info received from arbstore");
			const cut = parseFloat(info.cut);
			if (!info.address || !validationUtils.isValidAddress(info.address) || isNaN(cut) || cut < 0 || cut >= 1) {
				return cb("malformed info received from ArbStore");
			}
			info.url = url;
			arbStoreInfos[arbiter_address] = info;
			cb(null, info);
		});
	});
}
```
