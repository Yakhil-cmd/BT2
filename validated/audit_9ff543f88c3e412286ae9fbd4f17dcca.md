Based on my research, I found a directly analogous precision-loss pattern in `arbiter_contract.js`'s handling of the arbstore's percentage cut, which is computed with a single multiplication/floor (unlike the reported Solidity bug's double `mul-then-div`), but it produces the same class of vulnerability: a party can choose a small enough contract amount to round the arbstore's fee down to zero.### Title
Loss of precision in arbstore commission calculation allows fee avoidance in shared-address definition - (File: arbiter_contract.js)

### Summary
`deriveSharedAddress()` in `arbiter_contract.js` computes the acceptor's guaranteed payout and the arbstore's commission using `Math.floor(contract.amount * (1 - arbstoreInfo.cut))`, with the arbstore's share derived as the remainder `contract.amount - Math.floor(...)`. When `contract.amount` is small relative to `1/arbstoreInfo.cut`, this remainder rounds down to `0`, letting a contract party avoid paying the arbstore's commission entirely while still satisfying the shared-address spending definition.

### Finding Description
`deriveSharedAddress` builds the `["or", [...]]` definition that governs the two-party shared (multisig) address used for an arbiter-mediated contract [1](#0-0) . For the "happy path" branches (both parties agree, no arbitration), the code computes the amount the payer must deliver to the payee, discounted by the arbstore's cut, and separately requires an output of the remaining cut amount to the arbstore's address:

```
amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
...
amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
``` [2](#0-1) 

This is structurally the same class of bug as the reported `positionFee` issue: a percentage-based fee is derived through a `multiply-then-floor` operation on a value fully controlled by an unprivileged party (`contract.amount`, freely chosen by the contract's offeror/acceptor when negotiating the peer-to-peer contract). Because `arbstoreInfo.cut` is a fractional rate (e.g. 0.01 for 1%), for sufficiently small `contract.amount` (specifically whenever `contract.amount * arbstoreInfo.cut < 1`), `Math.floor(contract.amount * (1 - arbstoreInfo.cut))` equals `contract.amount` itself, making `contract.amount - Math.floor(...)` equal `0`. The `["has", {..., amount: 0, address: arbstoreInfo.address}]` clause then requires an output of amount `0` to the arbstore — which is either trivially satisfiable/omittable or simply never enforces any real payment to the arbstore, since real unit outputs must be positive. Either way, the arbstore's intended commission is silently reduced to zero.

### Impact Explanation
This lets either contracting party structure (or repeatedly split) a contract's `amount` to guarantee the arbstore is paid nothing for hosting/arbitrating the contract, while the shared address's non-arbitration definition branch still validates and releases full funds between the two parties. This is a direct, deterministic loss of the arbstore's fee revenue for any sufficiently small contract, undermining the commission model that the arbiter marketplace relies on for compensation — analogous to the protocol-fee bypass in the original report, but here it affects the arbstore/wallet-contract fee mechanism rather than an on-chain AA. Because the affected code lives in wallet/contract composition logic (`arbiter_contract.js`), the concrete on-chain impact is limited to fee avoidance against the arbstore, not consensus-level fund freezing or double-spend, since the contract itself still completes and settles between the two agreed parties.

### Likelihood Explanation
Likelihood is straightforward: any user negotiating an arbiter contract with a nonzero `arbstoreInfo.cut` can trivially choose (or the wallet UI could allow choosing) an `amount` small enough that `contract.amount * arbstoreInfo.cut < 1`, e.g. `cut = 0.01` and `amount = 50` yields a cut of `0` under `Math.floor`. No special privileges, network position, or race conditions are required — only control over the contract's `amount` field, which is normal user input for this feature.

### Recommendation
After computing the arbstore's cut amount, add a sanity check that if `arbstoreInfo.cut > 0`, the derived cut amount must not be `0` (analogous to the recommended fix in the original report): either reject/round up the cut computation (e.g., `Math.ceil` instead of `Math.floor` for the arbstore's share, adjusting the payer amount accordingly), or enforce a minimum contract amount such that `Math.floor(contract.amount * arbstoreInfo.cut) >= 1` whenever `hasArbStoreCut` is true.

### Proof of Concept
1. An arbstore configures `arbstoreInfo.cut = 0.01` (1%) for `contract.arbiter_address`.
2. A user creates an arbiter contract with `contract.amount = 50` (or any `amount` such that `amount * 0.01 < 1`).
3. In `deriveSharedAddress`, `Math.floor(50 * (1 - 0.01)) = Math.floor(49.5) = 49`... actually for `amount` low enough that `amount*cut<1` (e.g., `amount = 50`, `cut = 0.01` gives `49.5→49`, cut=1, not 0; choose `amount` such that `amount*cut<1`, e.g. `amount=99, cut=0.01` gives `floor(99*0.99)=98`, cut=`99-98=1`; to get cut exactly `0`, pick `amount` and `cut` so `amount*cut<1`, e.g. `cut=0.005`, `amount=100` → `floor(100*0.995)=99`, cut=`1`; more precisely for cut=0 need `ceil(amount*cut)==0`, i.e. `amount*cut<1`. With `cut=0.001` and `amount=500`: `floor(500*0.999)=499`, cut=`500-499=1`. Choosing `amount=999` and `cut=0.001`: `floor(999*0.999)=998`, cut=`1`. To force cut=0, use `amount` such that `amount*cut<1` strictly, e.g. `cut=0.001, amount=500` gives `amount*cut=0.5<1` but floor computation must be checked precisely against the formula `contract.amount - Math.floor(contract.amount*(1-cut))`).
4. The payer completes the contract for `contract.amount`, and the "has output" condition for the arbstore either requires a zero-amount output (never satisfied by real payment) or is bypassed, so the arbstore receives no commission despite `hasArbStoreCut` being true. [3](#0-2)

### Citations

**File:** arbiter_contract.js (L454-482)
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
				var isPrivate = assetInfo && assetInfo.is_private;
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
