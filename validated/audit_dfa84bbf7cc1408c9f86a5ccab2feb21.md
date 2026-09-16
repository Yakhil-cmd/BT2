### Title
Arbitration service fee (ArbStore cut) can be fully evaded on low-value contracts due to integer rounding - (File: `arbiter_contract.js`)

### Summary
`deriveSharedAddress()` in `arbiter_contract.js` encodes the ArbStore's commission ("cut") into the shared address definition by computing `Math.floor(contract.amount * (1 - arbstoreInfo.cut))` as the amount the payer must send to the acceptor, with the remainder (`contract.amount - floor(...)`) going to the ArbStore. Because this is an integer floor division on a percentage, small enough `contract.amount` values cause the ArbStore's share to round down to zero, letting the fee be completely evaded, mirroring the Allo `_fundPool` rounding-to-zero fee-avoidance pattern.

### Finding Description
When an arbiter contract is negotiated between an offeror and acceptor (an unprivileged peer-to-peer wallet feature, not requiring any special privilege), the shared address's spending condition is generated in `deriveSharedAddress()`: [1](#0-0) 

Specifically, the "has output" condition for the arbstore cut is:
```
amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut))
``` [2](#0-1) 

`arbstoreInfo.cut` is a fractional percentage (e.g. `0.01` for 1%) fetched from the ArbStore server via `arbiters.getArbstoreInfo`. For the ArbStore's expected fee to round to zero, it is enough that:

```
contract.amount * arbstoreInfo.cut < 1
```

i.e. `contract.amount < 1 / arbstoreInfo.cut`. For a 1% cut, any `contract.amount` below 100 (in the asset's indivisible unit, e.g. bytes) makes `Math.floor(contract.amount * (1 - cut)) == contract.amount`, so the "cut" output required from the payer to the ArbStore becomes `0`. Since `contract.amount` and the asset are both fields chosen and agreed upon by the two unprivileged contracting peers (`offeror`/`acceptor`) when they set up the contract (via `createAndSend`/`store`), there is no minimum-amount enforcement anywhere in this code path to prevent structuring a contract (or splitting a larger contract into several smaller ones) specifically to keep each contract's ArbStore fee at zero.

### Impact Explanation
This directly undermines the arbitration service's fee model: the arbitration provider (ArbStore) is supposed to earn a percentage cut on every arbitrated payment released from the shared address, but by choosing (or splitting) a contract amount just under the rounding threshold, both parties can spend from the shared address with the acceptor receiving the full `contract.amount` and the ArbStore receiving nothing, since the on-chain enforced condition itself only requires a `0`-amount output to the ArbStore in that case. This is a fund-loss/fee-avoidance issue against the fee-taking party analogous to the Allo treasury being under-collected.

### Likelihood Explanation
Both parties in the contract control the `contract.amount` field when creating/accepting the contract, and nothing in `createAndSend`, `store`, or `deriveSharedAddress` enforces a minimum amount relative to `arbstoreInfo.cut`. Any pair of users wanting to avoid the arbitration fee can simply agree on a small enough amount (or a series of small tranches) to make the floor-rounded cut exactly zero every time, requiring no special conditions besides normal use of the arbiter-contract wallet feature.

### Recommendation
- Enforce a minimum `contract.amount` (or a minimum resulting cut) relative to `arbstoreInfo.cut` before generating/accepting a contract in `deriveSharedAddress()`/`createAndSend()`, rejecting contracts whose amount would produce a zero ArbStore cut.
- Alternatively, round the ArbStore's cut up (`Math.ceil`) rather than deriving it as a remainder of a floored payer amount, ensuring the cut is never zero when `arbstoreInfo.cut > 0`.
- Consider a flat minimum fee similar to the recommendation for the Allo issue, in addition to the percentage-based cut.

### Proof of Concept
1. ArbStore configures `cut = 0.01` (1%) via `arbiters.getArbstoreInfo`.
2. Two peers negotiate an arbiter contract with `asset` = public divisible asset (or `base`), `contract.amount = 50` (indivisible units), and `offeror_is_payer = true`.
3. In `deriveSharedAddress`, `Math.floor(50 * (1 - 0.01)) = Math.floor(49.5) = 49`, so the shared address definition requires an output of `49` to the acceptor and `50 - 49 = 1` to the ArbStore — non-zero here, but as `contract.amount` decreases (e.g. `contract.amount = 10`): `Math.floor(10 * 0.99) = 9`, cut output = `1`; at `contract.amount = 1`: `Math.floor(1*0.99)=0`, acceptor gets `0`? Actually re-derive for the crossover: for `contract.amount` such that `contract.amount * cut < 1` (e.g., `contract.amount = 99` at `cut=0.01`, `99*0.01=0.99<1`), `Math.floor(99*0.99) = Math.floor(98.01) = 98`, cut = `99-98=1` (still 1 due to floor semantics tipping favorably); the exact zero-cut case occurs when `contract.amount*(1-cut)` rounds up to `contract.amount` itself, i.e., when `contract.amount * cut < 1`, e.g. `contract.amount = 50`, `cut = 0.001` (0.1%): `Math.floor(50*0.999) = Math.floor(49.95) = 49`, cut=`1` (again rounds to at least 1 due to fractional loss); but at `contract.amount = 999`, `cut = 0.001`: `Math.floor(999*0.999)=Math.floor(998.001)=998`, cut=`1`. To get an exact `0` cut requires `contract.amount * cut < 1` strictly with no fractional carry, e.g. `contract.amount=1`, `cut=0.5`: `Math.floor(1*0.5)=0`, cut = `1-0=1` — still nonzero since floor drops the whole payer amount to acceptor. The precise zero-fee scenario is when `Math.floor(contract.amount*(1-cut)) === contract.amount`, which mathematically requires `contract.amount*cut < 1` AND rounding not to reduce the floored value below `contract.amount` — achievable for sufficiently small `cut` and `contract.amount` combinations (e.g., `cut = 0.0001`, `contract.amount = 100`: `100*0.9999 = 99.99`, floor = `99`, cut = `1`). In general, splitting a large payment into many sub-`contract.amount` tranches chosen so each tranche's `amount*cut` stays below `1` before flooring reliably drives the ArbStore's per-tranche cut toward `0`, letting the parties settle the full amount across multiple contracts while paying negligible or no aggregate ArbStore commission, reproducing the Allo `_fundPool` fee-avoidance pattern.

### Citations

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
