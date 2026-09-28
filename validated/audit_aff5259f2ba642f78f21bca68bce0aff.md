### Title
Bad-debt floor resurrects wiped supply shares and drains later deposits - ([File: `contracts/pool/src/interest.rs`])

### Summary
When bad debt equals or exceeds total supplied value, `apply_bad_debt_to_supply_index` computes a zero post-loss supply index but clamps it upward to `SUPPLY_INDEX_FLOOR_RAW`, equal to `RAY/1000`. [1](#0-0) [2](#0-1) 

That clamp leaves every pre-cleanup scaled supply position with a positive residual claim even though the loss consumed the entire supply side. [3](#0-2) 

An unprivileged caller can trigger the write-down through `clean_bad_debt`, and an owner of an affected supply position can later withdraw the phantom claim through `withdraw`. [4](#0-3) [5](#0-4) [6](#0-5) 

### Finding Description
`apply_bad_debt_to_supply_index` caps the write-off at total supplied value, computes `remaining / total_supplied_value`, and derives the new index from that reduction factor. [7](#0-6) 

For a complete wipeout, `remaining` is zero and the mathematically correct new index is zero, but the final `.max(SUPPLY_INDEX_FLOOR_RAW)` restores it to `RAY/1000`. [8](#0-7) 

The permissionless controller cleanup admits an account only when its debt exceeds collateral and collateral is no more than the bad-debt dust threshold. [9](#0-8) [10](#0-9) 

Cleanup sends each remaining borrow position to `pool_seize_positions_call`; on the pool’s `Borrow` side, the position value becomes `bad_debt`, is applied to the supply index, and the debt shares are burned. [11](#0-10) [12](#0-11) 

Because controller account positions retain their old `scaled_amount`, an index formerly near `RAY` leaves approximately 0.1% of each old position’s pre-write-down value spendable after a complete wipeout. [13](#0-12) [3](#0-2) 

A later deposit is minted and credited at the floored index, preserving the new supplier’s claim while making its tokens available to satisfy the old phantom claim. [14](#0-13) 

A full withdrawal resolves all old shares against current cash, passes the reserve check, debits cash, and transfers the resulting amount to the position owner. [6](#0-5) [15](#0-14) [16](#0-15) 

The repository’s own regression model demonstrates that the residual claim withdraws exactly the fresh deposit and leaves insufficient cash for the fresh supplier’s claim. [17](#0-16) 

### Impact Explanation
This creates unbacked withdrawal rights after the socialized loss should have reduced old supplier claims to zero. [18](#0-17) 

A holder of pre-write-down shares can extract newly deposited tokens up to the residual claim, permanently impairing the later supplier whose accounting claim remains intact but whose cash backing was removed. [17](#0-16) 

The resulting market has supplier claims exceeding cash plus outstanding debt, which is the backing-shortfall condition guarded elsewhere by `require_backed_market`. [19](#0-18) 

### Likelihood Explanation
The attacker needs only an existing supply position in the affected hub asset and an insolvent account whose remaining collateral is at or below the dust cap. [9](#0-8) 

Once such an account exists, `clean_bad_debt(caller, account_id)` is permissionless and requires only caller authorization. [20](#0-19) [4](#0-3) 

The precondition can arise from price movement, accrued interest, liquidation sequencing, or repeated write-downs; the vulnerable state transition itself does not require governance access, leaked authority, or an external contract callback. [21](#0-20) 

### Recommendation
Do not clamp a mathematically zero post-write-down index upward while old scaled supply shares remain withdrawable. [8](#0-7) 

Represent a complete write-down as zero-valued old shares, and add an explicit first-deposit/bootstrap path for subsequent deposits so a zero index does not become a conversion divisor. [22](#0-21) 

Alternatively, introduce a market generation or equivalent reset mechanism so pre-cleanup scaled positions cannot be converted or withdrawn under the post-reset index. [23](#0-22) 

Add an end-to-end regression that performs `clean_bad_debt`, makes a fresh `supply`, then attempts a full `withdraw` of an old position and asserts that the old claim pays zero. [24](#0-23) 

### Proof of Concept
1. Attacker owns account `A` holding scaled supply shares in `(hub_id, debt_asset)`, while an unrelated or attacker-controlled account `B` has debt in the same market. [25](#0-24) 
2. `B` becomes eligible for cleanup: `total_debt > total_collateral` and `total_collateral <= BAD_DEBT_USD_THRESHOLD`. [9](#0-8) 
3. Any address submits `clean_bad_debt(caller, B_id)`; cleanup emits a `PoolSeizeEntry` with `side = AccountPositionType::Borrow` for each remaining debt position. [20](#0-19) [11](#0-10) 
4. In the pool, `bad_debt >= total_supplied_value`, so `reduction_factor = 0`; the code nevertheless stores `SUPPLY_INDEX_FLOOR_RAW`. [12](#0-11) [18](#0-17) 
5. If `A` previously held shares worth `1,000,000` units at approximately `RAY`, those shares now retain a phantom value of approximately `1,000` units. [3](#0-2) 
6. A victim submits `supply(caller, V_id, spoke_id, [((hub_id, debt_asset), 1_000)])`, crediting `1,000` units of cash to the same market. [25](#0-24) [14](#0-13) 
7. The attacker submits `withdraw(caller, A_id, [((hub_id, debt_asset), 0)], to)`; the zero amount selects the full position, resolves the old shares into `1,000` gross units, debits cash, and transfers them to `to`. [26](#0-25) [6](#0-5) 
8. The market’s cash is now zero while the victim’s `1,000`-unit supply claim remains, leaving the victim permanently unable to withdraw the deposited funds. [17](#0-16)

### Citations

**File:** contracts/pool/src/interest.rs (L73-88)
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
```

**File:** contracts/pool/README.md (L18-35)
```markdown
Two persistent keys per market, and **no per-user storage anywhere**:

```text
PoolKey::Params(HubAssetKey)   # InterestRateModel fields, asset id, decimals
PoolKey::State(HubAssetKey)    # supplied, borrowed, revenue, indexes, ts, cash
```

Balances are **scaled shares**, not amounts. A share is multiplied by a market
index to get present value, so interest accrues to every holder at once
without touching per-user state:

```text
supply value = supplied * supply_index      debt value = borrowed * borrow_index
```

Positions arrive as arguments (`ScaledPositionRaw`) and leave as return values
(`PoolPositionMutation`). The controller holds the ledger; the pool holds the
aggregates.
```

**File:** contracts/pool/README.md (L187-190)
```markdown
`borrow_index` only ever grows — `update_borrow_index` is its sole writer.
`supply_index` is **not** monotone: `apply_bad_debt_to_supply_index` scales it
down to socialize a loss across suppliers, floored at `SUPPLY_INDEX_FLOOR_RAW`
(`RAY/1000`). Anything caching an index must tolerate a decrease.
```

**File:** contracts/pool/tests/interest.rs (L372-427)
```rust
#[test]
fn test_raw_cache_floor_clamp_strands_claim_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let old_scaled_raw = 1_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: old_scaled_raw,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let old_scaled = Ray::from(old_scaled_raw);

        apply_bad_debt_to_supply_index(&mut cache, Ray::from(5_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout clamps supply_index UP to RAY/1000 instead of resetting shares to 0",
        );

        let stranded = cache.unscale_supply_floor(old_scaled);
        assert!(stranded > 0, "floor clamp leaves S_old a phantom claim");
        assert_eq!(
            cache.cash(),
            0,
            "no cash yet: invariant only masked by require_reserves"
        );

        let fresh_cash = stranded;
        let fresh_scaled = cache.calculate_scaled_supply(fresh_cash);
        cache.mint_supply(fresh_scaled);
        cache.credit_cash(fresh_cash);

        let fresh_claim = cache.unscale_supply_floor(fresh_scaled);
        assert_eq!(
            fresh_claim, fresh_cash,
            "fresh supplier's claim equals deposit"
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, old_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded wiped position pays out real tokens");
        assert_eq!(gross, fresh_cash, "S_old drains exactly the fresh deposit");
        assert!(
            cache.cash() < fresh_claim,
            "pool cash ({}) can no longer cover fresh supplier claim ({}): funds lost",
            cache.cash(),
            fresh_claim,
        );
    });
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-199)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L222-237)
```rust
    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L21-49)
```rust
    let mut entries: Vec<PoolSeizeEntry> = Vec::new(env);
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Supply,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Deposit,
            position: (&position).into(),
        });
    }
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

**File:** contracts/pool/src/ops/withdraw.rs (L93-99)
```rust
fn resolve_close_or_partial(cache: &Cache, amount: i128, position: Ray) -> (Ray, i128) {
    let (burned, gross_amount) = cache.resolve_withdrawal(amount, position);
    assert_with_error!(
        cache.env(),
        gross_amount == 0 || burned.raw() > 0,
        GenericError::WithdrawRoundsToZeroShares
    );
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

**File:** contracts/controller/src/positions/liquidation/curve.rs (L23-27)
```rust
/// Admits socialization when debt exceeds collateral and collateral is at or
/// below `BAD_DEBT_USD_THRESHOLD` (WAD USD).
pub(crate) fn is_socializable_bad_debt(total_debt: Wad, total_collateral: Wad) -> bool {
    total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
}
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

**File:** contracts/pool/src/cache/cash.rs (L46-52)
```rust
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
```

**File:** contracts/pool/src/guards.rs (L49-65)
```rust
/// Panics with `PoolInsolvent` if the market has a positive backing shortfall.
///
/// Backing = cash + ceiled debt value; claims = floored supply value.
pub(crate) fn require_backed_market(env: &Env, cache: &Cache) {
    assert_with_error!(
        env,
        backing_shortfall(cache) == 0,
        CollateralError::PoolInsolvent
    );
}

/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
```

**File:** contracts/controller/src/lib.rs (L160-164)
```rust
    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
```

**File:** contracts/pool/src/cache/scale.rs (L29-37)
```rust
    /// Converts an asset deposit into scaled supply shares (floor at the supply index).
    pub(crate) fn calculate_scaled_supply(&self, amount: i128) -> Ray {
        calculate_scaled_supply(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.supply_index,
        )
    }
```

**File:** contracts/controller/README.md (L73-78)
```markdown
| `supply` | `fn supply( env: Env, caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>, ) -> u64` | blocked by global pause | Supplies `assets` as collateral to `account_id` in spoke `spoke_id`, creating a new account when `account_id` is 0, and returns the account id. |
| `borrow` | `fn borrow( env: Env, caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>, )` | blocked by global pause | Borrows `borrows` against `account_id`'s collateral, sending the funds to `to` if provided or to the caller otherwise; reverts if the resulting position breaches the account's solvency limits. |
| `withdraw` | `fn withdraw( env: Env, caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>, ) -> Vec<(HubAssetKey, i128)>` | — | Withdraws `withdrawals` from `account_id`'s supplied collateral, sending the funds to `to` if provided or to the caller otherwise, and returns the amounts actually withdrawn; a zero amount for an asset withdraws the entire position. |
| `repay` | `fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | — | Repays `payments` against `account_id`'s debt positions, pulling the funds from the caller and refunding any excess. |
| `liquidate` | `fn liquidate( env: Env, liquidator: Address, account_id: u64, debt_payments: Vec<(HubAssetKey, i128)>, seize_mode: SeizeMode, ) -> u64` | — | Liquidates `account_id` by having `liquidator` repay `debt_payments` and seizing collateral at a bonus scaled by the account's health factor. Returns the `Credit` receiver's account id, or 0 for `Transfer`. |
| `clean_bad_debt` | `fn clean_bad_debt(env: Env, caller: Address, account_id: u64)` | — | Socializes `account_id`'s debt into the supply index and removes the account when it is insolvent and its remaining collateral value is at or below the dust threshold; reverts otherwise. |
```
