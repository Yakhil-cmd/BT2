### Title
Suppliers can withdraw before a predictable bad-debt write-down and shift the entire loss onto remaining suppliers - (File: contracts/pool/src/ops/seize.rs)

### Summary
In XOXNO Lending, bad debt is socialized by lowering the debt market's `supply_index` at the moment `seize`/`clean_bad_debt`/`force_socialize_bad_debt` executes, not when the account becomes insolvent. Until that call runs, `backing_shortfall` values the unrecoverable debt at face value, so a supplier who sees the coming write-down can call `withdraw` and exit at the pre-write-down index, concentrating the entire loss on whoever stays. This is the direct analog of the Arcadia "withdraw before bad auction" issue, and it is reachable by any unprivileged supplier through the controller `withdraw` entrypoint.

### Finding Description
- Bad-debt socialization happens only inside `apply` in `contracts/pool/src/ops/seize.rs:24-28`: the borrow-side entry calls `interest::apply_bad_debt_to_supply_index` and burns the debt shares. The supply index is unchanged until a liquidation or cleanup call executes it.
- The write-down formula (`docs/reference/formulas.md:390-395`) spreads `bad_debt_ray` over the *current* `total_supply_ray`. Every share withdrawn before the call escapes the loss entirely; the same absolute debt is written down against fewer shares, so each remaining share loses more.
- The only exit gates are `require_reserves` (cash covers the draw), `require_utilization_below_max`, and `require_supply_for_debt` (`contracts/pool/src/guards.rs:19-73`). Critically, `require_backed_market` gates `supply` only — "Backing shortfall blocks entry, not exit" (`contracts/pool/README.md:286-288`). And `backing_shortfall` (`guards.rs:61-66`) counts outstanding debt at face (`unscale_borrow_ceil`), so a market that is economically insolvent shows no shortfall until the write-down is applied.
- The insolvency is public, predictable state: once a price move pushes `D > C`, anyone can see that the next `liquidate`/`clean_bad_debt` will write the index down, and withdraw before that transaction lands. `INV-HALT-01` explicitly keeps withdrawal callable even under global pause (`docs/reference/invariants.md:490-491`).
- Unlike Arcadia's `notDuringAuction` modifier, there is no equivalent guard here at all — withdrawal is simply never checked against pending socialization.

### Impact Explanation
Passive suppliers absorb a disproportionate share — up to all — of socialized bad debt. The in-repo test `supplier_can_exit_ahead_of_bad_debt_writedown` (`tests/test-harness/tests/controller/bad_debt_index.rs:401-473`) demonstrates a ~4x loss amplification on the remaining supplier when a 75% supplier exits first, and `exit_then_clean_then_re_enter_dodges_the_write_down_when_utilization_allows` (`tests/test-harness/tests/composition/supplier_exit_before_socialization_is_bounded_by_utilization.rs:52-79`) shows the dodge can be done atomically: withdraw → `clean_bad_debt` → re-supply in one invocation, keeping the full stake while another supplier eats the whole write-down. This is theft of supplier value via loss transfer, a Medium-severity economic analog.

### Likelihood Explanation
Requires only an unprivileged `withdraw` call while an account is observably insolvent. The utilization cap bounds the exit size only when `max_utilization < RAY` and utilization is high; with unbounded max utilization or low utilization, a full exit succeeds. The last remaining supplier cannot fully exit (`require_supply_for_debt`), which guarantees someone is always left holding the loss. Predictability is inherent: insolvency is derivable from public prices and positions well before any cleanup transaction.

### Recommendation
Apply the report's suggested mitigation adapted to the share-index model:
- Add a withdrawal delay/queue: a `withdraw` request marks shares "exiting" (still exposed to index write-downs) and only becomes claimable after a cooldown, so insolvency cannot be frontrun.
- Alternatively, value debt conservatively in `backing_shortfall`/withdrawal paths — e.g., discount debt of accounts known `D > C` — so exits settle at the post-write-down value. This is harder since the pool has no per-account book (INV-ACCT-10).
- Short of that, an asymmetric guard: `require_utilization_below_max` on withdrawal could compare against post-write-down utilization rather than the pre-write-down snapshot.

### Proof of Concept
Existing in-repo tests reproduce both halves of the attack:

1. `tests/test-harness/tests/controller/bad_debt_index.rs:401` — `supplier_can_exit_ahead_of_bad_debt_writedown`: Bob (75% of ETH supply) and Carol (25%) supply; Alice borrows ETH against USDC; USDC price crashes making Alice insolvent; Bob calls `withdraw` before any liquidation, recovers his full deposit; the subsequent `liquidate` writes the entire debt down on Carol's shares, amplifying her loss ~4x versus the passive scenario.

2. `tests/test-harness/tests/composition/supplier_exit_before_socialization_is_bounded_by_utilization.rs:52` — atomic `withdraw` + `clean_bad_debt` + `supply` via the script runner: the runner keeps its whole stake while BOB absorbs the entire write-down, proving a single unprivileged address can dodge and re-enter in one transaction whenever utilization permits.

Root cause chain: `seize::apply` defers the write-down to call time (`contracts/pool/src/ops/seize.rs:24-28`), `backing_shortfall` values debt at face until then (`contracts/pool/src/guards.rs:61-66`), and no backing or socialization guard runs on `withdraw` (`contracts/pool/README.md:269-297`).