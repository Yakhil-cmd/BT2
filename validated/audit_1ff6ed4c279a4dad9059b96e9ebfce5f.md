### Title
Front-running `clean_bad_debt` lets a supplier withdraw at the pre-write-down supply index, shifting the socialized loss onto remaining suppliers - (contracts/pool/src/interest.rs)

### Summary
`clean_bad_debt` is a permissionless entrypoint: any address can trigger bad-debt cleanup once an account's ceil risk debt exceeds half-up collateral and collateral is at or below the $5 dust threshold [1](#0-0) . Cleanup calls `apply_bad_debt_to_supply_index`, which multiplies the market's `supply_index` by `floor(remaining/total_supplied)` — a sudden, discrete drop in the share price, exactly analogous to Carapace's `lockCapital` reducing `totalSTokenUnderlying` [2](#0-1) . Withdrawals are converted at the *current* index via `resolve_withdrawal`/`unscale_supply_floor` [3](#0-2) , and unlike Carapace there is no request/cooldown cycle: `withdraw` is a single transaction. A supplier who front-runs the cleanup exits at the high index; suppliers who don't absorb a proportionally larger write-down because `total_supplied_value` shrinks while the `bad_debt` amount written off is unchanged.

### Finding Description
The write-down math is `new_index = floor(old_index * (V - min(D,V))/V)` where `V = supplied * supply_index` and `D` is the ceiled bad-debt value [4](#0-3) . Alice's withdrawal burns shares at the pre-write-down index and debits cash [5](#0-4) . Since burning shares reduces `supplied` (hence `V`) before cleanup executes, the *same* debt `D` produces a strictly smaller `reduction_factor`, i.e. a deeper index cut for everyone remaining. A debt-free supplier's withdraw passes all gates: `require_reserves`, the utilization ceiling (INV-ACCT-08 does not bind a debt-free exit above the cap only if utilization exceeds max — see below), and `require_supply_for_debt` [6](#0-5) .

Numeric example mirroring the report: market with `supplied` worth 1,000,000 units at index 1.0; Alice and Bob each hold 100,000 shares-equivalent. Pending `clean_bad_debt` writes off 500,000 of debt. Alice front-runs, withdraws 100,000 (index still 1.0). Now `V = 900,000`, `D = 500,000` → `reduction = 4/9` → index 0.4444. Bob's 100,000 shares now claim only ~44,444 units. Alice extracted 55,556 units more than Bob for identical holdings.

One caveat I could not fully verify in the available iterations: `guards::require_utilization_below_max` is skipped only for liquidations, so if the write-down market is at/above its utilization ceiling, the front-running withdraw reverts [7](#0-6) . The attack is therefore conditional on utilization headroom, which commonly exists since a heavily defaulted market need not be at the cap.

### Impact Explanation
Theft of user funds / redistribution: the front-runner converts an imminent, publicly observable socialized loss into full-value claims, so remaining suppliers bear a larger loss than their pro-rata share. The loss transferred equals the victim's share of the extra write-down depth — unbounded relative to the $5 dust threshold, since `D` itself is arbitrary.

### Likelihood Explanation
Medium. `clean_bad_debt` eligibility (`total_debt > total_collateral`, collateral ≤ $5) is computable from public state, and the transaction is permissionless and mempool/sequence observable on Stellar, where inclusion order can be influenced via fee bidding [8](#0-7) . Requirements: the front-runner holds a withdrawable supply position in the affected market, has no binding health constraint (debt-free, or withdraw retains HF ≥ 1), the market has utilization headroom and sufficient `cash` to cover the withdrawal. No privileged role is needed by the attacker — unlike Carapace, the victim need not even queue a withdrawal in advance.

### Recommendation
- Settle withdrawals against the *post-cleanup* index when a socializable account exists, or more practically: gate `withdraw`/`supply` exits on a market where a pending known-insolvent cleanup has been observed, or execute the bad-debt write-down *before* honouring withdrawals within the same index epoch.
- Cheaper option: have `clean_bad_debt` and `liquidate`'s post-liquidation cleanup path write down the index against the `supplied` value snapshot taken at accrual time, or credit a virtual `pending_bad_debt` reserve so front-running withdrawals cannot enlarge `V`'s denominator effect. Alternatively require exits in markets with outstanding socializable debt to burn shares at `min(index, index_if_cleanup_applied)`.

### Proof of Concept
1. Market M: suppliers Alice and Bob each hold 100,000 shares-equivalent; total supply value 1,000,000; index = 1.0. Utilization below max, cash ≥ Alice's claim.
2. A borrower account becomes insolvent: `total_debt > total_collateral`, collateral ≤ $5 (permissionless `clean_bad_debt` eligible), bad debt `D = 500,000`.
3. Keeper submits `clean_bad_debt(account_id)` [9](#0-8) .
4. Alice observes it and submits `withdraw(spoke_id, M, amount=0)` (withdraw-all sentinel) with a higher fee so it sequences first. Pool burns her shares at index 1.0 and pays 100,000 [10](#0-9) .
5. `clean_bad_debt` executes: `apply_bad_debt_to_supply_index` computes `reduction = (900,000 - 500,000)/900,000 = 4/9`, index → 0.4444 [11](#0-10) .
6. Bob withdraws his identical 100,000 shares-equivalent and receives ~44,444. Alice profited 55,556 units at Bob's expense.

### Citations

**File:** docs/reference/invariants.md (L463-470)
```markdown
### INV-LIQ-04 — Bad-debt socialization is explicit and total

Permissionless cleanup requires ceil risk debt greater than half-up unweighted
collateral and collateral at or below the fixed $5 dust threshold. Owner-only
forced cleanup omits the dust cap. Both require debt, readable account and NFT
state, valid required prices and no active flash guard. Listing flags and
global pause do not block standalone cleanup.

```

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** common/src/rates/scaling.rs (L105-121)
```rust
pub fn resolve_withdrawal(
    env: &Env,
    amount: i128,
    pos_scaled: Ray,
    supply_index: Ray,
    decimals: u32,
) -> (Ray, i128) {
    let current_supply_actual = unscale_supply(env, pos_scaled, supply_index, decimals);
    let current_supply_floor = unscale_supply_floor(env, pos_scaled, supply_index, decimals);
    if amount >= current_supply_actual {
        return (pos_scaled, current_supply_floor);
    }
    (
        calculate_scaled_supply_ceil(env, amount, decimals, supply_index),
        amount,
    )
}
```

**File:** contracts/pool/src/ops/withdraw.rs (L65-79)
```rust
    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
    let net_transfer = withhold_liquidation_fee(
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);
```

**File:** contracts/pool/src/ops/withdraw.rs (L93-118)
```rust
fn resolve_close_or_partial(cache: &Cache, amount: i128, position: Ray) -> (Ray, i128) {
    let (burned, gross_amount) = cache.resolve_withdrawal(amount, position);
    assert_with_error!(
        cache.env(),
        gross_amount == 0 || burned.raw() > 0,
        GenericError::WithdrawRoundsToZeroShares
    );
    (burned, gross_amount)
}

/// Burns `burned` from market supply and returns the user's remaining scaled position.
fn burn_position(env: &Env, cache: &mut Cache, position: Ray, burned: Ray) -> Ray {
    cache.burn_supply(burned);
    position.checked_sub(env, burned)
}

/// Enforces reserve, utilization, and solvency guards, then debits cash for
/// the net transfer. Liquidations and footprint-only closes skip utilization.
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L313-315)
```rust
    if is_socializable_bad_debt(totals.total_debt, totals.total_collateral) {
        bad_debt::execute_bad_debt_cleanup(env, cache, account_id, account, totals);
    }
```
