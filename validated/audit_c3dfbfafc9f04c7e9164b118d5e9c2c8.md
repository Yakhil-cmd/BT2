### Title
Utilization-cap withdrawal freeze: borrowing to `max_utilization` plus permissionless accrual permanently reverts every non-liquidation `withdraw` - (File: contracts/pool/src/guards.rs)

### Summary
The bug class behind CVE-2018-3277 is a repeatable service-hang/crash induced through a legitimate request path. The analog in XOXNO Lending is a repeatable market-level denial of service: `require_utilization_below_max` in `contracts/pool/src/guards.rs:19-34` is an absolute post-state check applied to every non-liquidation `withdraw` (`contracts/pool/src/ops/withdraw.rs:111-119`), while `borrow` is allowed to land utilization exactly at `max_utilization` (`<=`, `contracts/pool/src/ops/borrow.rs:78`) and the permissionless `update_indexes` path (`interest::global_sync`, `contracts/pool/src/interest.rs:20-33`) grows the debt numerator every millisecond. Any unprivileged borrower can push utilization to the cap and then let ordinary interest accrual tip it over, after which *all* supplier withdrawals in that market revert with `UtilizationAboveMax` — a hang of the market's exit path.

### Finding Description
`mint_debt` enforces `borrowed.div_ceil(supplied) <= max_utilization`, so a borrower may borrow until utilization is exactly at the cap (guard uses `<=`, `guards.rs:31`). The check compares *ceiled debt value* against *floored supply value* at current indexes. Because `global_sync` accrues the borrow index on every subsequent call and `update_indexes`/`accrue` is permissionless, the attacker (or simply the next ledger) advances `borrow_index`, raising the numerator with no new borrow. From that instant:

- `withdraw` (non-liquidation) → `UtilizationAboveMax` (127), for every supplier, for any amount, since the guard tests the *post-burn market* and burning supply shares only raises utilization further.
- `claim_revenue` → also reverts (`UtilizationAboveMax` per `contracts/pool/README.md:148`).
- `supply` is not utilization-gated, but large fresh supply is the only non-debt way back below the cap.

The only releases are debt repayment (borrower incentive-dependent) or liquidation-driven withdrawals, which bypass the guard (`withdraw.rs:114` — `skip_utilization_check` for `is_liquidation || empty_close`). On a market with `max_utilization < RAY` (the cap is only disabled at exactly `RAY`, `guards.rs:20`), a single unprivileged address holding a collateralized position can therefore freeze all supplier exits and treasury revenue claims.

### Impact Explanation
Temporary freezing of user funds and unclaimed yield: every supplier's `withdraw` reverts, and `claim_revenue` reverts, for as long as utilization stays above `max_utilization`. Duration is attacker-influenced — an attacker controlling the dominant debt can simply refuse to repay; on Stellar there is no forced repayment. Suppliers retain nominal share claims (exit is not permanently destroyed; recapitalization-like relief via new supply or repayment exists), so the correct classification is temporary freeze, Medium severity. Note `require_liquidation_buffer` (`guards.rs:39-47`) is a separate cash holdback and does not prevent reaching the utilization cap, since it compares cash draw against 2% of supply, not the ratio.

### Likelihood Explanation
Fully unprivileged and single-transaction reachable: `controller::borrow` → pool `borrow`/`mint_debt` sets utilization to exactly `max_utilization`; a subsequent permissionless `update_indexes` call (or any later transaction touching the market, since every entrypoint runs `global_sync` first, `interest.rs:20-33`) advances `last_timestamp` and raises utilization past the cap. No price oracle movement, no privileged call, and no collusion required. The cost is the interest on a position the attacker fully collateralized — they can even structure it so their own HF stays healthy while suppliers are locked.

### Recommendation
Apply the utilization cap to exits asymmetrically: skip `require_utilization_below_max` in `gate_and_debit` whenever the withdrawal does not increase utilization (e.g., allow withdrawals that only burn supply while debt is unchanged, or cap-check the pre-withdraw state rather than the post-state), or make the guard compare `min(post_util, pre_util)` so a withdrawal can never *push* the market over the cap but can always execute when the market is already above it. Alternatively, reserve a permanent utilization headroom inside `mint_debt` (e.g., require `util <= max_utilization - margin`) sized so accrual cannot silently cross the hard cap within one accrual chunk.

### Proof of Concept
1. Market exists with `max_utilization = 0.95 RAY`, supplied = 1,000,000 units, cash = 1,000,000.
2. Attacker supplies collateral in a second market and calls `controller::borrow` → pool `borrow` for 950,000 units. `mint_debt` passes: `require_reserves` (cash ≥ draw, `guards.rs:44`), `require_liquidation_buffer` (cash left = 50,000 ≥ 2% × 950,000 ≈ 19,000+ — sized to pass), and `require_utilization_below_max` (util = exactly 0.95, `<=` passes).
3. Attacker (or anyone) calls pool `update_indexes` one millisecond later. `global_sync` (`interest.rs:20-33`) grows `borrow_index`; post-state utilization > 0.95.
4. Any supplier calls `withdraw` for any positive amount → `gate_and_debit` → `require_utilization_below_max` → panic `UtilizationAboveMax` (`withdraw.rs:114-115`, `guards.rs:29-33`). Same for `claim_revenue`. All exits remain frozen until a repayment or a liquidation leg (which passes `is_liquidation = true` and skips the guard) reduces debt below the cap.