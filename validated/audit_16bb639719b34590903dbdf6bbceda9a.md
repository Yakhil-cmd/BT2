### Title
Headers commission is permanently lost (never credited to any address) when all candidate child units for a parent unit are final-bad - ([File: headers_commission.js])

### Summary
The Olas finding shows that `calculateStakingIncentives` silently drops staking incentives instead of refunding them when the epoch's total voting weight is zero — funds that were "available" are neither distributed to a recipient nor returned to the issuer, and are permanently lost. `ocore` has a structurally identical class of bug in `calcHeadersCommissions()`: headers-commission funds that a parent unit has already earmarked for a winning child are simply skipped and never inserted into `headers_commission_contributions` when the set of eligible children turns out to be empty, permanently burning the commission with no possibility of anyone ever claiming it.

### Finding Description
`calcHeadersCommissions()` (sqlite path) determines, for every parent unit, the set of "candidate children" competing for the parent's `headers_commission` (children on the same or next MCI that reference the parent and have `sequence='good'`): [1](#0-0) 

If `arrCandidateChildren.length === 0` — i.e., every child that could have won the commission ended up `final-bad` (non-`sequence='good'`) — the code simply `return`s from the `forEach` iteration for that parent, without recording anything in `assocChildrenInfosRAM`: [2](#0-1) 

Because that parent is never added to `assocChildrenInfos`, it never appears in `assocWonAmounts`, and consequently `headers_commission_contributions` is never populated for that unit's `headers_commission`. There is no fallback path (e.g., crediting the payer's own author, or leaving the amount attached to a future eligible child) — the commission amount is not written anywhere and can never later be spent as a `headers_commission` input by `mc_outputs.calcEarnings`/`readNextSpendableMcIndex`.

This mirrors the Olas bug exactly in structure: an amount that is "available" (`stakingPoint.stakingIncentive` in Olas vs. `parent.headers_commission` in ocore) is computed and reserved, but the code path that should distribute-or-refund it hits a degenerate case (`totalWeightSum == 0` in Olas vs. `arrCandidateChildren.length === 0` in ocore) where the amount is dropped entirely instead of being redirected to a safe default recipient.

An unprivileged unit poster (or a set of colluding accounts constructing DAG children) can trigger this condition deterministically: post a parent unit, then have every unit that includes that parent as a `parent_unit` at MCI or MCI+1 be non-serial ("final-bad", i.e. becomes a loser in the non-serial/duplicate address resolution performed during stabilization). If none of the children referencing that parent end up with `sequence='good'`, the parent's headers commission is lost.

### Impact Explanation
This causes a silent, permanent loss of funds ("freezing"/burning) that were meant to be paid out as headers commission to whichever unit ends up witnessing/majority-including the parent. No account is ever credited, and the amount cannot be recovered through any subsequent commission-calculation pass (the parent has already been consumed from `since_mc_index` bookkeeping once `calcHeadersCommissions` advances `max_spendable_mci`). This reduces the effective circulating byte balance without a corresponding output — analogous to Olas's inflation-cap deduction, but here it is an outright burn of commission funds that legitimate network participants (light/full clients acting as candidate children/witnesses) should have received. This does not enable unauthorized spending or double-spend, but it is a concrete, deterministic loss of funds belonging to the network's fee-distribution mechanism, matching the "Medium" classification the Olas judge assigned to the analogous finding.

### Likelihood Explanation
The triggering condition — a parent unit whose only candidate children (units built directly on top of it within the ±1 MCI window) all end up final-bad — is rare in benign operation but is reachable by any unprivileged unit poster who deliberately creates conflicting/non-serial units that reference the same parent, since non-serial resolution happens automatically during stabilization and does not require any special privilege, hub cooperation, or leaked keys. It requires deliberate DAG construction but no elevated access, making it a moderate-likelihood, fully attacker-reachable condition through ordinary unit posting.

### Recommendation
When `arrCandidateChildren.length === 0` for a parent unit, do not silently drop the `headers_commission`. Instead, either (a) carry the amount forward and re-attempt distribution among children discovered in later MCIs before the amount is considered "settled", or (b) fall back to crediting the commission to the parent unit's own author address(es) (analogous to how Olas's recommended fix refunds unclaimed incentives back into tokenomics inflation instead of burning them), and record that this payer_unit's commission has already been resolved so it cannot be double-counted if candidate children later appear.

### Proof of Concept
1. Post unit `P` (parent) that includes some `headers_commission`.
2. Construct two or more units `C1`, `C2` that both include `P` as a parent, arranged so that during stabilization both `C1` and `C2` end up being resolved as non-serial ("final-bad", `sequence != 'good'`), e.g. by making them conflict with each other or with another descendant, so that `arrSameMciChildren`/`arrNextMciChildren` filtered by `sequence === 'good'` is empty for `P`.
3. Allow the DAG to stabilize past `P`'s MCI so `calcHeadersCommissions()` runs with `since_mc_index` covering `P`.
4. Observe in `headers_commission.js` line 107-108 that `assocChildrenInfosRAM[P.unit]` is never set (`return` is hit), so `P`'s `headers_commission` is never inserted into `headers_commission_contributions` for any address — confirm via `SELECT * FROM headers_commission_contributions WHERE unit=P` returning no rows, while `P.headers_commission` amount remains permanently unclaimable and unspendable by any address.

### Citations

**File:** headers_commission.js (L100-108)
```javascript
								var next_mc_unit = next_mc_unit_props.unit;
								var filter_func = function(child){
									return (child.sequence === 'good' && child.parent_units && child.parent_units.indexOf(parent.unit) > -1);
								};
								var arrSameMciChildren = storage.assocStableUnitsByMci[parent.main_chain_index].filter(filter_func);
								var arrNextMciChildren = storage.assocStableUnitsByMci[parent.main_chain_index+1].filter(filter_func);
								var arrCandidateChildren = arrSameMciChildren.concat(arrNextMciChildren);
								if (arrCandidateChildren.length === 0)
									return; // all eligible children are final-bad, nobody gets the hc
```
