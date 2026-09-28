### Title
Bad-debt write-down floor resurrects wiped supplier claims - (File: contracts/pool/src/interest.rs)

### Summary
When bad debt equals or exceeds the market’s total supplied value, `apply_bad_debt_to_supply_index` computes a zero write-down factor but clamps the supply index to `RAY / 1_000`, preserving a residual 0.1% claim for all pre-existing supply shares instead of zeroing them. [1](#0-0) [2](#0-1) 

### Finding Description
`clean_bad_debt` is permissionless and reaches `execute_bad_debt_cleanup`, which submits every remaining borrow position to `pool_seize_positions_call`. [3](#0-2) [4](#0-3) 

For each borrow entry, the pool converts the debt shares with `unscale_borrow_ceil_ray`, calls `apply_bad_debt_to_supply_index`, and burns the debt. [5](#0-4) 

If `bad_debt >= total_supplied_value`, `remaining` and `reduction_factor` become zero, so `new_supply_index` becomes zero; the final `.max(SUPPLY_INDEX_FLOOR_RAW)` incorrectly raises it to `RAY / 1_000`. [6](#0-5) 

The corresponding supply shares are not burned, so a withdraw-all request still unscales those shares at the floored index, debits available cash, and transfers tokens to the supplier. [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
A total write-down leaves a claim worth up to 0.1% of the prior supplied value even though the economic write-down exhausted all supplier claims. [6](#0-5) [2](#0-1) 

Those phantom claims can consume later cash credited through recapitalization, repayment, liquidation receipts, or other settlement paths, causing theft of funds that should no longer be allocated to wiped suppliers and potentially recreating market insolvency. [10](#0-9) [11](#0-10) 

The checked-in test case demonstrates the accounting consequence directly: after the index clamps to the floor, the old shares retain a positive claim and can drain newly credited cash. [12](#0-11) 

### Likelihood Explanation
An attacker only needs to hold supply shares before a market undergoes a complete bad-debt write-down; either the attacker or any other caller can then invoke `clean_bad_debt` once the account is insolvent and its collateral is within the dust threshold. [3](#0-2) [13](#0-12) 

Extraction is conditional on the market later receiving cash, but the residual shares persist indefinitely and normal withdraw-all handling treats them as valid supplier claims. [14](#0-13) [15](#0-14) 

### Recommendation
Represent a complete write-down explicitly instead of clamping it to a live positive index: burn or mark all existing supply shares as wiped, block new supply until the market is reset, and special-case any subsequent zero-index operations. [16](#0-15) 

At minimum, remove `SUPPLY_INDEX_FLOOR_RAW` from this path and add a persisted wiped-market flag so `resolve_withdrawal`, supply minting, revenue claims, and utilization checks cannot reinterpret old shares at a synthetic 0.1% index. [17](#0-16) [18](#0-17) 

### Proof of Concept
1. An attacker supplies `1_000_000` units of a zero-decimal asset, receiving `1_000_000 RAY` scaled supply at an initial `supply_index` of `RAY`. [19](#0-18) 
2. A borrower’s account becomes eligible for cleanup with debt greater than or equal to the market’s entire supplied value; the attacker calls `clean_bad_debt(attacker, victim_account_id)`. [3](#0-2) [20](#0-19) 
3. The pool computes `reduction_factor = 0`, calculates `new_supply_index = 0`, and then stores `RAY / 1_000`, leaving the attacker’s shares claimable for `1_000` units rather than zero. [6](#0-5) [2](#0-1) 
4. Once at least `1_000` units are later credited to market cash, the attacker calls `withdraw(attacker, attacker_account_id, [(hub_asset, 0)], None)`; the zero leg maps to `i128::MAX`, resolves as a full withdrawal, passes the cash reserve check, and transfers the phantom balance. [7](#0-6) [9](#0-8)

### Citations

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

**File:** common/src/constants/pool.rs (L6-9)
```rust
/// Minimum value the supply index is clamped to when bad debt is written down against
/// suppliers, in raw ray units. Interest accrual does not apply this floor; it only guarantees
/// the index never decreases.
pub const SUPPLY_INDEX_FLOOR_RAW: i128 = RAY / 1_000;
```

**File:** contracts/controller/src/lib.rs (L160-164)
```rust
    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L35-49)
```rust
    for (hub_asset, position) in iter_debt_positions(&account.borrow_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Borrow,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Borrow,
            position: (&position).into(),
        });
    }
    let pool_addr = cache.cached_pool_address();
    pool_seize_positions_call(env, &pool_addr, &entries);
```

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/controller/src/positions/supply.rs (L189-198)
```rust
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
```

**File:** common/src/rates/scaling.rs (L105-120)
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
```

**File:** contracts/pool/src/ops/withdraw.rs (L93-100)
```rust
fn resolve_close_or_partial(cache: &Cache, amount: i128, position: Ray) -> (Ray, i128) {
    let (burned, gross_amount) = cache.resolve_withdrawal(amount, position);
    assert_with_error!(
        cache.env(),
        gross_amount == 0 || burned.raw() > 0,
        GenericError::WithdrawRoundsToZeroShares
    );
    (burned, gross_amount)
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

**File:** contracts/pool/src/ops/repay.rs (L54-58)
```rust
    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);

```

**File:** contracts/pool/src/cache/cash.rs (L15-52)
```rust
    pub(crate) fn require_reserves(&self, amount: i128) {
        assert_with_error!(
            self.env,
            self.cash >= amount,
            CollateralError::InsufficientLiquidity
        );
    }

    /// Increases accounting cash by `amount`. Rejects negative amounts and overflow.
    pub(crate) fn credit_cash(&mut self, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        self.cash = self
            .cash
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(&self.env, GenericError::MathOverflow));
    }

    /// Decreases accounting cash by `amount`. Rejects negative amounts or
    /// insufficient reserves.
    pub(crate) fn debit_cash(&mut self, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        self.require_reserves(amount);
        self.cash = self
            .cash
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(&self.env, GenericError::MathOverflow));
    }

    /// Transfers `amount` of the market asset from the pool to `recipient`.
    ///
    /// Rejects negative amounts; zero is a no-op. Does not adjust accounting cash.
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
```

**File:** contracts/pool/tests/interest.rs (L316-369)
```rust
#[test]
fn test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let scaled_a_raw = 1_000_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: scaled_a_raw,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let scaled_a = Ray::from(scaled_a_raw);

        apply_bad_debt_to_supply_index(&mut cache, Ray::from(2_000_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout must clamp supply index UP to the floor, not reset the base"
        );

        let stranded = cache.unscale_supply_floor(scaled_a);
        assert!(stranded > 0, "floor clamp leaves userA a phantom claim");
        assert_eq!(cache.cash(), 0, "empty market: no cash to extract yet");

        let c = stranded;
        let scaled_b = cache.calculate_scaled_supply(c);
        cache.mint_supply(scaled_b);
        cache.credit_cash(c);

        let b_claim = cache.unscale_supply_floor(scaled_b);
        assert_eq!(b_claim, c, "userB's honest claim equals their deposit");

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, scaled_a);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded position pays out non-zero");
        assert_eq!(
            gross, c,
            "userA drains exactly userB's fresh deposit out of the pool"
        );

        assert!(
            cache.cash() < b_claim,
            "pool cash ({}) can no longer cover userB's claim ({}): honest supplier lost funds",
            cache.cash(),
            b_claim
        );
        assert_eq!(cache.cash(), 0, "userA drained the pool to empty");
    });
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L23-27)
```rust
/// Admits socialization when debt exceeds collateral and collateral is at or
/// below `BAD_DEBT_USD_THRESHOLD` (WAD USD).
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
```

**File:** contracts/pool/src/ops/supply.rs (L26-39)
```rust
    guards::require_backed_market(env, &cache);

    let minted = cache.calculate_scaled_supply(amount);
    assert_with_error!(
        env,
        amount == 0 || minted.raw() > 0,
        GenericError::SupplyRoundsToZeroShares
    );

    position = position.checked_add(env, minted);
    cache.mint_supply(minted);

    cache.credit_cash(amount);

```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-237)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```
