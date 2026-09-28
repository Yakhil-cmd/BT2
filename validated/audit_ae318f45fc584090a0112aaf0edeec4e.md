### Title
Supplier withdrawals and borrows treat revenue-backed cash as free liquidity, draining the funds owed to unclaimed protocol revenue - ([File: contracts/pool/src/guards.rs](contracts/pool/src/guards.rs))

### Summary
The pool tracks a single `cash` ledger that implicitly contains the tokens backing unclaimed protocol revenue shares. Neither `require_reserves` nor `require_liquidation_buffer` subtracts the outstanding revenue claim before allowing a withdrawal, borrow, or strategy draw. An unprivileged supplier can therefore withdraw (or a borrower borrow) the exact tokens that collateralize the treasury's accrued revenue, leaving `claim_revenue` paying zero.

### Finding Description
`Cache::require_reserves` only checks `self.cash >= amount` (`contracts/pool/src/cache/cash.rs:15-21`), and `gate_and_debit` for withdrawals adds only utilization and supply-for-debt guards before `debit_cash` (`contracts/pool/src/ops/withdraw.rs:111-119`). Borrows go through `mint_debt`, which checks `require_reserves` plus `require_liquidation_buffer` — a flat 200 BPS of supplied value, not the revenue claim (`contracts/pool/src/ops/borrow.rs:63-67`, `contracts/pool/src/guards.rs:39-47`).

Meanwhile revenue is minted as supply shares inside `supplied`, but its token backing is just part of the same `cash` balance, and `claim_revenue` pays only `min(cash, floor(revenue_value))` (`docs/reference/formulas.md`, `contracts/pool/README.md:337-346`). Nothing reserves that amount for the revenue claim, exactly analogous to Unitas counting portfolio-held funds inside total reserves: the liquidity checks report funds as available that are already owed to another claim.

### Impact Explanation
Once utilization is high (repayment is the only cash inflow), a supplier's full withdrawal or a strategy/borrow draw can take `cash` down to near zero while `get_revenue` reports a large accrued claim. `claim_revenue` then returns `actual_amount = 0` and moves no tokens — the unclaimed yield is frozen for as long as the market stays drained, and if the market later takes bad debt that writes down the supply index, the revenue claim is written down with it and never paid. This is theft/freezing of unclaimed yield reachable by any supplier or borrower.

### Likelihood Explanation
Reachable by a single unprivileged address through the controller `withdraw` or `borrow` entrypoints (or `multiply`/`create_strategy` which share `mint_debt`). It requires accrued revenue plus high utilization — a routine state on an actively borrowed market — and no privileged action. The exit path is even favored: liquidations skip the utilization guard entirely, so a liquidation withdrawal can drain revenue-backing cash even at the cap.

### Recommendation
Reserve the floored revenue claim inside the liquidity checks: change `require_reserves` call sites for `withdraw`/`borrow`/`create_strategy`/`flash_loan` to require `cash - draw >= floor(revenue_value)` (or at minimum fold it into `require_liquidation_buffer`), so user draws cannot consume tokens backing unclaimed revenue.

### Proof of Concept
1. Alice supplies 1000 USDC; Bob borrows up to the liquidation buffer so `cash` is small; time passes and revenue accrues (`revenue_value > 0`).
2. Bob repays just enough that `cash` exceeds the revenue claim, then Alice withdraws her full supply via `controller.withdraw` — `require_reserves` passes because `cash >= amount` even though `cash - amount < floor(revenue_value)`.
3. `controller.claim_revenue` now pays `min(cash, revenue_value)`, i.e. less than the accrued claim (or zero if cash is fully drained), while `get_revenue` still reports the claim. The shortfall is exactly the revenue-backing cash that the withdrawal was allowed to consume.