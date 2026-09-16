### Title
Arbiter-declared winner can drain the entire shared-address balance while bypassing the ArbStore fee, unlike the normal completion path — ([File: arbiter_contract.js])

### Summary
`deriveSharedAddress()` in `arbiter_contract.js` builds a 5-branch `"or"` spending definition for the multisig `shared_address` that holds contract funds. The two "normal completion" branches (`arrDefinition[1][1]` / `[1][2]`) strictly enforce, via `"has" {what:"output", ...}` conditions, that the ArbStore's cut is paid to `arbstoreInfo.address` whenever a party spends. The two "arbiter dispute resolution" branches (`arrDefinition[1][3]` / `[1][4]`), however, only require that the winning address sign together with the arbiter's `"in data feed"` declaration — they carry **no** `"has" output` restriction at all. This is the same fee-inconsistency pattern as the FixedPrice.sol report: the fee/cut is enforced on one exit path but silently skipped on another equivalent exit path of the same escrow, letting whoever wins the dispute walk away with the entire balance (including any extra/accidental funds sent to the shared address) while denying the ArbStore its fee.

### Finding Description
In `deriveSharedAddress()`: [1](#0-0) 

For non-private, non-fixed-denomination assets, the offeror/acceptor completion branches enforce the cut: [2](#0-1) 

But the dispute-resolution branches, `arrDefinition[1][3]` and `[1][4]`, are only:
```
["and", [ ["address", offeror_address], ["in data feed", [[contract.arbiter_address], "CONTRACT_"+contract.hash, "=", offeror_address]] ]]
["and", [ ["address", acceptor_address], ["in data feed", [[contract.arbiter_address], "CONTRACT_"+contract.hash, "=", acceptor_address]] ]]
```
No `"has"` output constraint is attached to these two branches (they are never modified after their initial placeholder assignment at lines 474-480), unlike branches 1 and 2. Consequently, once the arbiter posts a `data_feed` unit naming a winner (a routine part of the intended dispute flow — see `openDispute`/`parseWinnerFromUnit`), that single winning address can single-handedly compose and sign a unit spending the **entire** balance of `shared_address` to any output(s) of its choosing:
- The `contract.amount` cap enforced in branches 1/2 (via the fixed `"has"` output amount) is absent here.
- The ArbStore cut enforced via `hasArbStoreCut`/`"has" {address: arbstoreInfo.address}` in branches 1/2 is likewise absent.

This mirrors the FixedPrice.sol root cause exactly: the platform/service fee is computed and enforced on the "happy path" (`arrDefinition[1][1]`/`[1][2]` in `deriveSharedAddress`, analogous to `_end()`'s fee deduction), but the alternative exit path (`arrDefinition[1][3]`/`[1][4]`, analogous to `cancel()`) has no corresponding, consistent treatment — except in the opposite direction: instead of over-charging a fee where none should apply, ocore under-enforces it, letting the winner appropriate the ArbStore's due cut and any unexpected extra balance.

### Impact Explanation
Whichever party the arbiter rules in favor of can spend the full `shared_address` balance without paying the agreed ArbStore cut (`arbiter_contract.js` lines 484, 500, 509, 518 show the cut is a first-class, expected part of contract settlement). This is a direct fund loss for the ArbStore/arbiter service — the fee that is otherwise guaranteed by the shared-address definition in the normal-completion case is entirely bypassable in the dispute-resolution case. It also means the winner is not limited to `contract.amount`: if additional funds ever land in the shared multisig address (e.g., extra outputs from either party, similar to the accidental extra ETH transfer in the original report), the dispute-winning address can claim that excess too, again with no fee and no cap, since the has-output amount checks that exist on branches 1/2 are absent on branches 3/4.

### Likelihood Explanation
Opening a dispute and having the arbiter declare a winner is the designed, expected workflow of `arbiter_contract.js` (`openDispute`, `parseWinnerFromUnit`, the `"in_dispute"`/`"dispute_resolved"` states), reachable by either ordinary contract party (payer or payee) simply by having a legitimate, non-malicious arbiter resolve a dispute in the normal course of business. No malicious node/hub/arbiter behavior is required — an honest arbiter data-feed declaration is sufficient to expose the missing fee/cap enforcement, so likelihood is high whenever a contract that reaches dispute has any balance beyond the pure win/lose amount, or whenever the ArbStore expects to be paid its cut on dispute-based settlements as it is on normal ones.

### Recommendation
Mirror the enforcement used in the offeror/acceptor completion branches (`arrDefinition[1][1]`/`[1][2]`) inside the two dispute-resolution branches (`arrDefinition[1][3]`/`[1][4]`) in `deriveSharedAddress()`:
- Add a `"has" {what: "output", asset, amount: contract.amount (minus cut if applicable), address: winner}` restriction to cap what the winner may claim to `contract.amount`.
- When `hasArbStoreCut` is true and the asset is not fixed-denomination, also require a `"has"` output paying `arbstoreInfo.address` its cut, exactly as done for branches 1/2, so that ArbStore's fee is consistently collected regardless of whether settlement happens via normal completion or via arbiter dispute resolution.
- Add the same `"not" ["has", {what:"input", address:"other address"}]` anti-combination safeguard that branches 1/2 already have.

### Proof of Concept
1. Payer and acceptor create an arbiter contract for `amount` bytes with a non-zero ArbStore cut; `deriveSharedAddress()` builds the 5-branch `"or"` definition as shown above.
2. Payer pays `amount` (or more, e.g. due to a mistaken/extra transfer) into `shared_address` (`pay()` at `arbiter_contract.js:692-716`).
3. A dispute is opened (`openDispute`) and the arbiter posts a legitimate `data_feed` unit `CONTRACT_<hash> = <winner_address>` (normal arbiter workflow, `parseWinnerFromUnit`).
4. The winning address alone signs and posts a unit spending the *entire* balance of `shared_address` to itself — this satisfies branch `[1][3]`/`[1][4]` of the "or" definition, since that branch only checks `["address", winner]` + `["in data feed", ...]`, with no `"has"` output constraint capping the amount or requiring the ArbStore cut to be paid.
5. The ArbStore never receives its cut, and if extra funds were present in `shared_address`, the winner keeps them too — unlike the enforced, capped, fee-inclusive payout that `arrDefinition[1][1]`/`[1][2]` require for normal (non-disputed) completions.

### Citations

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
