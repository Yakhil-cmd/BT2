### Title
Interest accrual past `max_utilization` permanently reverts all supplier withdrawals while a solvent borrower refuses to repay - (File: contracts/pool/src/guards.rs)

### Summary
`withdraw` (and `claim_revenue`, `net_settle`) run `require_utilization_below_max`, a post-state check that rejects when `ceil(borrowed × borrow_index) / floor(supplied × supply_index) > max_utilization`. Because the check is evaluated after interest accrual and the numerator grows every millisecond with outstanding debt, an unprivileged borrower can push utilization to just under the cap, stay fully collateralized so liquidation never unlocks, and let passive interest accrual tip utilization over the cap — after which every supplier withdrawal and protocol revenue claim on that market reverts with `UtilizationAboveMax` (127). Funds stay frozen until the borrower voluntarily repays.

### Finding Description
Every pool mutation accrues interest first (`Cache::load` → `interest::global_sync` → mutate → guards). For exits, the guard chain then runs `require_utilization_below_max` in `contracts/pool/src/guards.rs:19-34`:

```rust
let borrowed = cache.borrowed().mul_ceil(env, cache.borrow_index());
...
let supplied = cache.supplied().mul_floor(env, cache.supply_index());
assert_with_error!(
    env,
    supplied > Ray::ZERO && borrowed.div_ceil(env, supplied) <= cache.params().max_utilization,
    CollateralError::UtilizationAboveMax
);
```

Two properties make this attacker-reachable:

1. **The numerator only grows.** `borrow_index` is monotone non-decreasing (`update_borrow_index` is its sole writer, capped at `MAX_BORROW_INDEX_RAY`). With any outstanding debt, `borrowed.mul_ceil(borrow_index)` strictly increases over time, so utilization drifts upward with no new borrows needed.
2. **Exit cannot fix itself.** Burning supply shares shrinks the denominator, so a withdrawal that is over the cap stays over the cap; the guard is an absolute post-state test, not a "don't make it worse" test. The pool README itself states "once utilization reaches the cap no withdrawal of any size passes" (`contracts/pool/README.md`, Guards section).

The attacker path needs no privilege:

- `controller.supply(caller, collateral…)` then `controller.borrow(caller, …)` to draw the market's cash until utilization sits just below `max_utilization` (borrows are gated by the same guard, so the attacker lands just under it).
- Keep the borrowing account healthy via over-collateralization so `liquidate`/`clean_bad_debt` never trigger — liquidation withdrawals do bypass the cap, but nothing forces them to happen on a solvent account.
- Wait for accrual (or call the permissionless `controller.update_indexes(caller, hub_assets)`, which requires only `caller.require_auth()` and no role) to push `borrowed × borrow_index` over `max_utilization × supplied`.
- From that point, `withdraw`, `withdraw_all`, `claim_revenue`, and `repay_debt_with_collateral` (which ends in a withdraw leg) all revert on this market. The only unblockers are the attacker's own `repay`/`net_settle`, or `recapitalize`, which requires new outside capital equal to the shortfall.

The accrual-then-check ordering in `interest.rs:20-33` (`global_sync` runs before guards on every entrypoint) means even a previously-passing withdrawal can start failing purely because time elapsed.

### Impact Explanation
Temporary freezing of funds at market scale: every supplier's principal and yield, plus all unclaimed protocol `revenue`, in that `(hub, token)` market is unwithdrawable for as long as the borrower keeps the position open and solvent. Unlike insolvency-freeze scenarios, no loss event is required — the freeze is a pure consequence of the utilization guard applied to exits combined with monotone debt accrual. The attacker pays only borrow interest on their own position and can unfreeze at will by repaying, making this a low-cost, reversible griefing/hold-to-ransom vector against all suppliers of a market.

### Likelihood Explanation
Low-to-medium. It requires the attacker to hold a large fraction of the market's debt (borrow capacity permitting), keep the account's health factor above 1 indefinitely (price movements can force liquidation, which bypasses the cap), and accept ongoing interest cost. On thinly supplied markets with high caps this is cheap to stage; on deep markets the capital requirement is large. No privileged action, oracle manipulation, or timing luck is needed — `update_indexes` is permissionless and accrual is deterministic.

### Recommendation
Make the utilization cap a gate on *entry* (new debt), not on *exit*, mirroring the documented backing-shortfall asymmetry. Options:

- Skip `require_utilization_below_max` for `withdraw` when the withdrawal does not increase utilization's numerator — i.e., evaluate `pre_borrowed ≤ max_utilization × post_supplied`, allowing any withdrawal while debt is unchanged, or
- Allow withdrawals up to the amount that keeps utilization non-increasing (`min(requested, cash)`, checking `util_post ≤ util_pre`), and
- Keep the guard on `claim_revenue`/`net_settle` only if revenue claims can worsen utilization; since claims burn revenue shares (denominator), apply the same non-increasing rule.

Alternatively, exempt withdrawals when utilization crossed the cap solely due to accrual (compare against utilization computed at `last_timestamp`), so dormancy can never trap suppliers.

### Proof of Concept
1. Market M lists token T with `max_utilization = 0.95 RAY`; suppliers have supplied S units.
2. Attacker supplies ample collateral in market C and calls `controller.borrow(attacker, M, amount)` sized so that post-borrow utilization is e.g. 0.949.
3. Attacker (or anyone) calls `controller.update_indexes(attacker, [M])` after time passes. `global_sync` raises `borrow_index`; `borrowed.mul_ceil(borrow_index)` now exceeds `0.95 × supplied.mul_floor(supply_index)`.
4. Any supplier calls `controller.withdraw(supplier, M, …)` → pool `withdraw` runs `global_sync` then `require_utilization_below_max` → `borrowed.div_ceil(supplied) > max_utilization` → panics `UtilizationAboveMax` (127). Same for `claim_revenue`.
5. Attacker keeps HF > 1 (over-collateralized in C), so `liquidate` reverts `NotLiquidatable`-style and `clean_bad_debt` is ineligible. The freeze persists until the attacker repays, demonstrating temporary freezing of all market funds by a single unprivileged address.