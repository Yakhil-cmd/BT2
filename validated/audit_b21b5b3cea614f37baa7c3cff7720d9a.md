## Analysis

This maps to a real analog in the arbiter-contract shared-address escrow logic in `arbiter_contract.js`. The core issue mirrors the reported bug class: a spending authorization is granted to a party but is not scoped/capped to the amount it should cover, so once granted it can be used to drain funds beyond what was intended — the escrow-address equivalent of an "unspent approval" that is never bounded or revoked.

### Title
Arbiter-decided dispute-resolution branches of the escrow shared-address definition grant unbounded, uncapped spending rights to the winner - (File: arbiter_contract.js)

### Summary
`deriveSharedAddress()` builds the AND/OR spending definition for an arbiter-contract escrow (multisig) address. For the normal "both sign" and "not disputed" branches, the definition constrains the payout with an explicit `has output {amount: contract.amount, address: ...}` clause and (when applicable) enforces the arbstore's cut. However, the two "arbiter decided" branches — reached after an `in data feed` declares a winner — have **no amount constraint at all** and never enforce the arbstore cut.

### Finding Description
In `deriveSharedAddress()`, the base definition template is: [1](#0-0) 

For non-private, non-fixed-denomination assets, branches `[1][1]` and `[1][2]` (mutual agreement) are overwritten with `has output {amount: contract.amount, address: ...}` constraints, and the arbstore cut is additionally enforced there: [2](#0-1) 

But branches `[1][3]` and `[1][4]` — the ones satisfied once the arbiter posts a `CONTRACT_<hash>` data feed naming a winner — are **never modified** to add any `has output` amount clause or arbstore-cut requirement: [3](#0-2) 

Since `in data feed` conditions only check that some oracle (the arbiter) posted a matching value — they don't reference amounts, don't get consumed, and data feeds are permanent once stable — as soon as the arbiter names a winner, that winner's `["address", X] AND ["in data feed", ...]` branch is satisfied indefinitely for **any** payment drawn from that shared address, for **any** amount currently held there, with no cap tied to `contract.amount` and no cut carved out for the arbstore. This is functionally the same root cause as the reported bug: a party is granted spending authority that is never bounded to what it should be allowed to spend, and is never revoked/reset after being used.

### Impact Explanation
Any funds held in the escrow shared address beyond `contract.amount` — e.g. if the payer over-funds the address, if additional payments accumulate at the same address, or if the address is reused across interactions — can be swept entirely by the arbiter-declared winner. The arbstore's cut, which is deducted in the "has" branches, is bypassed entirely through the arbiter-decision branches. This is unauthorized spending of counterparty/arbstore funds and can wipe the escrow balance beyond the contracted terms, since `validateAuthentifiers`' `in data feed` evaluation in `definition.js` imposes no amount restriction: [4](#0-3) 

### Likelihood Explanation
Any of the two arbiter-contract counterparties can reach this: they only need the shared address to hold more than `contract.amount` at dispute time (easily achievable by simply sending an extra payment to the well-known shared address, which is a normal witnessed multisig address accepting any inbound payment) and then have the arbiter (an oracle whose sole job is to publish `CONTRACT_<hash>=<winner>`) rule in their favor once — a routine, expected step of the dispute flow, not a compromise of the arbiter.

### Recommendation
Add the same `has output {asset, amount: contract.amount (or arbstore-adjusted amount), address: winner}` constraint (and arbstore-cut enforcement) to the arbiter-decision branches `arrDefinition[1][3]` and `arrDefinition[1][4]`, exactly as is already done for the mutual-agreement branches `arrDefinition[1][1]` / `[1][2]`, so the arbiter's decision can only authorize spending of the originally contracted amount (net of arbstore cut), not the address's entire balance.

### Proof of Concept
1. Offeror and acceptor create an arbiter contract for `contract.amount` GBYTE via `deriveSharedAddress()`, deriving shared address `S`.
2. Offeror funds `S` with `contract.amount`, then (accidentally or deliberately) sends an additional payment to `S` later.
3. A dispute is raised; the arbiter posts a data-feed unit with `CONTRACT_<hash> = acceptor_address`.
4. The acceptor composes and signs a payment from `S` using signing path `r.4` (`["address", acceptor_address]` AND `["in data feed", ...]`) for the full current balance of `S`, which the definition permits since branch `[1][4]` has no `has output` amount constraint.
5. The acceptor receives the entire balance of `S`, not just `contract.amount`, and the arbstore's cut is never enforced for this path.

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

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```
