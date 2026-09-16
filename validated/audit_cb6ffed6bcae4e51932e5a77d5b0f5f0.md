## Analog Found

### Title
Unbounded arbstore fee ("cut") lets a chosen arbitration service claim up to half of a contract's escrowed funds - ([File: arbiters.js])

### Summary
The report's bug class is: a privileged party can set an unbounded fee/percentage parameter that is later applied to funds a counterparty expects to fully receive, with no meaningful cap enforced by the protocol. The analog in this codebase is the arbstore `cut` parameter used by `arbiter_contract.js` when constructing the shared escrow address for an arbiter contract: `getArbstoreInfo()` only rejects values that are exactly `>= 1`, so any value up to just under 100% is accepted and baked into the on-chain spending definition of the escrow address.

### Finding Description
`arbiters.getArbstoreInfo()` fetches `cut` from the arbstore's own HTTP endpoint and validates it only with `isNaN(cut) || cut < 0 || cut >= 1`, i.e. any cut strictly less than 100% passes: [1](#0-0) 

This value is then used, unvalidated against any sane maximum, to compute the split between the contract counterparty and the arbstore when the shared (escrow) address definition is derived in `arbiter_contract.js`'s `deriveSharedAddress()`. The peer's payable amount is `Math.floor(contract.amount * (1 - arbstoreInfo.cut))`, and the remainder is assigned to the arbstore as an additional required output in the address definition: [2](#0-1) 

Once this definition is fixed and the shared address is derived, it becomes the actual, network-enforced spending condition for that address — any unit satisfying the `has output` clauses of the definition is valid regardless of what the local wallet software does. The only place that pushes back on an excessive cut is a client-side JS assertion inside `complete()`, which throws if `arbstore_amount > peer_amount` (i.e. caps it at 50% when releasing funds via this helper): [3](#0-2) 

That check is a convenience guard in one JS helper function, not a protocol-level constraint on the address definition itself. It doesn't reduce the amount actually assignable to the arbstore in the definition — the shared address is still created with any cut value up to (but not including) 100%.

### Impact Explanation
An arbstore that a user selects (or is directed to via the hub, per `hub/get_arbstore_url`) as the arbiter for a contract can report an unreasonably high `cut` (e.g. 40–49%) that is silently accepted and permanently embedded in the escrow address definition before either party inspects it closely. Because the offeror/payer sends the full `contract.amount` into this shared address in `pay()` without re-verifying the cut against a sane bound, the counterparty (the ordinary user relying on the arbitration outcome) can end up receiving far less than expected — up to half of the total escrowed amount can be diverted to the arbstore, which is well beyond any typical arbitration fee and is enforced by the underlying address definition, not by the JS "50%" assertion (which merely prevents one particular wallet helper from itself composing a transaction that goes further, but does not constrain the definition or protect the case where the split ≤50% but still unreasonably high).

### Likelihood Explanation
Likelihood is Low-to-Medium: it requires a user to engage a malicious/compromised arbstore service (chosen by address, but its fee is only checked at info-fetch time with no upper sanity bound), similar to the "malicious or compromised admin" precondition in the original report. No blockchain-level enforcement or resolution mechanism cross-checks the cut against a reasonable maximum before the escrow address (and its fund-losing spending path) becomes binding.

### Recommendation
Enforce a sane maximum bound on `cut` in `arbiters.getArbstoreInfo()` (e.g., a few percent, analogous to the report's "limit the fee rate to a maximum value, for example 3%") rather than only rejecting `cut >= 1`. Additionally, surface the cut prominently to both parties before contract creation/signing so it cannot pass unnoticed, and consider enforcing the cap in the address-definition construction (`deriveSharedAddress`) itself rather than only in one JS convenience function.

### Proof of Concept
1. Malicious arbstore reports `cut = 0.49` via its `/api/get_info` endpoint.
2. `getArbstoreInfo()` accepts it since `0.49 < 1`.
3. `deriveSharedAddress()` builds the escrow address definition giving the arbstore 49% of the contract amount as a hard-coded required output.
4. Payer calls `pay()`, sending the full `contract.amount` to this shared address.
5. On contract completion, `complete()`'s 50% guard does not trigger (49% < 50%), and the release transaction sends 49% of the funds to the arbstore instead of the small arbitration fee the counterparty expected. [4](#0-3)

### Citations

**File:** arbiters.js (L71-78)
```javascript
			const cut = parseFloat(info.cut);
			if (!info.address || !validationUtils.isValidAddress(info.address) || isNaN(cut) || cut < 0 || cut >= 1) {
				return cb("malformed info received from ArbStore");
			}
			info.url = url;
			arbStoreInfos[arbiter_address] = info;
			cb(null, info);
		});
```

**File:** arbiter_contract.js (L494-522)
```javascript
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

**File:** arbiter_contract.js (L692-716)
```javascript
function pay(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, function(objContract) {
		if (!objContract.shared_address || objContract.status !== "signed" || !objContract.me_is_payer)
			return cb("contract can't be paid");
		var opts = {
			asset: objContract.asset,
			to_address: objContract.shared_address,
			amount: objContract.amount,
			spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own'
		};
		if (arrSigningDeviceAddresses.length)
			opts.arrSigningDeviceAddresses = arrSigningDeviceAddresses;
		walletInstance.sendMultiPayment(opts, function(err, unit){								
			if (err)
				return cb(err);
			setField(objContract.hash, "status", "paid", function(objContract){
				cb(null, objContract, unit);
			});
			// listen for peer announce to withdraw funds
			storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
				if (assetInfo && assetInfo.is_private)
					db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.peer_address]);
			});
		});
	});
```

**File:** arbiter_contract.js (L752-763)
```javascript
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
```
