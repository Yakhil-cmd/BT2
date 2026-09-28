### Title
Accrued interest can push utilization past the cap and freeze all withdrawals — redemption is not guaranteed even with cash in the pool - ([contracts/pool/src/guards.rs](contracts/pool/src/guards.rs))

### Summary
The UbiquityPool report describes a redemption guarantee failure: claims can exceed what the pool can pay, so late redeemers are stuck. XOXNO Lending has the same failure shape through a different mechanism. `withdraw` is gated by `require_utilization_below_max`, an absolute post-state check on `ceil(debt)/floor(supply) <= max_utilization` [1](#0-0) . The `borrow` guard only enforces the cap at borrow time; `global_sync` accrual can push utilization over the cap afterwards, and burning supply shares in a withdrawal raises utilization further [2](#0-1) . Once utilization reaches `max_utilization`, every non-liquidation `withdraw` reverts with `UtilizationAboveMax` regardless of how much cash the pool physically holds.

### Finding Description
- An unprivileged user calls `controller::borrow` to push market utilization to just below `max_utilization`. Any holder of sufficient collateral can do this.
- Interest accrual then raises `borrowed * borrow_index` without any borrower action. `controller::update_indexes` is permissionless caller-auth maintenance, so anyone can force accrual on demand [3](#0-2) .
- `withdraw` runs `cache.require_reserves(net_transfer)` (book cash check), then `require_utilization_below_max` unless `is_liquidation`, then `require_supply_for_debt` [2](#0-1) . When utilization is already at/above the cap, the utilization assert fails for every withdrawal size, because burning shares can only increase `debt/supply`.
- The exit budget below the cap is therefore first-come-first-served: each successful withdrawal raises utilization toward the cap, and the protocol's own README acknowledges that "once utilization reaches the cap no withdrawal of any size passes" and that accrual alone pushes it there. Suppliers who exit late are stuck even though `cash` in the book (and the SAC balance) covers their claims — the direct analog of the bank run in the Ubiquity report, where the mechanism that fails is the redemption gate rather than the token balance.
- Liquidation withdrawals bypass the cap, so liquidations can keep draining cash while ordinary suppliers remain blocked [4](#0-3) .

### Impact Explanation
Temporary freezing of user funds: suppliers cannot withdraw any amount from an over-cap market until debt decreases (voluntary `repay`, or liquidation/cleanup of an underwater borrower). If borrowers are solvent-but-idle there is no forced release path — `liquidate` requires HF < 1 and `clean_bad_debt` requires insolvency plus dust-level collateral [5](#0-4) . Meanwhile suppliers continue earning only the sub-1 borrow-rate share while their principal is locked.

### Likelihood Explanation
High reachability, moderate trigger conditions. A single unprivileged account needs enough collateral to borrow utilization to the cap (large markets make this expensive), then time or permissionless `update_indexes` calls do the rest — `max_borrow_rate` can reach 2×RAY so accrual moves utilization quickly. Any third party can also push a near-cap market over the edge with `update_indexes` at zero cost.

### Recommendation
Make the utilization gate forgiving for exits: e.g. skip `require_utilization_below_max` when the caller's withdrawal does not increase utilization beyond its pre-withdrawal value, or permit withdrawals that keep post-state utilization at or below the pre-state level. Alternatively add a bounded grace: allow withdrawals up to `min(claim, cash)` pro-rata when over cap, or let `recapitalize`/repay release a proportional exit queue.

### Proof of Concept
1. Market `(hub, USDC)`: suppliers deposit S, `max_utilization < RAY`.
2. Attacker (own account, sufficient collateral) calls `controller::borrow(caller, account_id, [(key, amount)], to)` with `amount` sized so `ceil(debt)/floor(supply)` sits just under `max_utilization` — passes `require_reserves`, `require_liquidation_buffer`, and the cap check [6](#0-5) .
3. Attacker (or anyone) calls `controller::update_indexes(caller, [key])`; accrual raises `borrow_index`, pushing `borrowed.mul_ceil(borrow_index) / supplied.mul_floor(supply_index)` above `max_utilization`.
4. Any supplier calls `controller::withdraw` for any positive amount: `accounting` burns shares, `gate_and_debit` runs `require_utilization_below_max`, the assert fails → `UtilizationAboveMax` (127). Pool cash is sufficient (`require_reserves` passed) but the exit reverts.
5. State persists: the attacker's healthy position cannot be liquidated (`is_liquidatable` false), `clean_bad_debt` reverts (`CannotCleanBadDebt`), so no permissionless path restores exits until a borrower voluntarily repays.

### Citations

**File:** contracts/pool/src/guards.rs (L19-34)
```rust
pub(crate) fn require_utilization_below_max(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO || cache.params().max_utilization >= Ray::ONE {
        return;
    }

    let borrowed = cache.borrowed().mul_ceil(env, cache.borrow_index());
    if borrowed == Ray::ZERO {
        return;
    }
    let supplied = cache.supplied().mul_floor(env, cache.supply_index());
    assert_with_error!(
        env,
        supplied > Ray::ZERO && borrowed.div_ceil(env, supplied) <= cache.params().max_utilization,
        CollateralError::UtilizationAboveMax
    );
}
```

**File:** contracts/pool/src/ops/withdraw.rs (L111-118)
```rust
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
```

**File:** scripts/permissionless_entrypoints.txt (L74-74)
```text
controller::update_indexes | caller-auth | INV-AUTH-03, INV-IDX-04 | Keeper maintenance: accrues interest to the current ledger timestamp. Accrual never lowers the borrow or supply index and each chunk's rate is capped at max_borrow_rate, so the caller chooses only the accrual timing and cannot lower anyone's balance.
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-235)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);
```
