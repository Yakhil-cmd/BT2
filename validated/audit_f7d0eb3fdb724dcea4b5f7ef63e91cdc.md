### Title
Interest-accrual multiplication overflow can permanently freeze a saturated market - (File: common/src/rates/index.rs)

### Summary
An unprivileged user can push a market’s scaled debt or supply close to `i128::MAX`, then allow interest accrual to increase the corresponding index. Once `scaled_amount * index` exceeds the `i128` domain, every subsequent operation that accrues interest reverts, permanently preventing repayment, withdrawal, liquidation, and further market operation.

### Finding Description
`global_sync` runs before pool state changes and accrues interest through `accrue_step` for every elapsed chunk. [1](#0-0) 

During accrual, `calculate_supplier_rewards` computes both `borrowed * old_borrow_index` and `borrowed * new_borrow_index` using `Ray::mul`. [2](#0-1) 

`Ray::mul` uses exact intermediate multiplication but raises `MathOverflow` when the resulting RAY value does not fit in `i128`. [3](#0-2) 

Market totals are also bounded only by `i128`: debt and supply minting use checked addition, so they can reach values that fit initially but no longer fit after multiplication by a larger index. [4](#0-3) 

Although indexes are capped, the cap is approximately `10^9` times the initial index; it does not ensure that `scaled_amount * index` remains representable. [5](#0-4) 

Once the market crosses the representability boundary, the arithmetic panic occurs before the transaction commits. Because normal user operations accrue before mutating positions, later `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `update_indexes` calls continue to hit the same overflowing accrual.

### Impact Explanation
All funds represented by the affected market can become permanently frozen. Suppliers cannot withdraw because withdrawal accrues first, borrowers cannot repay or be liquidated through the normal paths, and administrators cannot safely recover the market through ordinary state transitions because those transitions also perform accrual.

This is more than a fail-closed input rejection: the market commits a valid historical state whose later, time-derived valuation becomes unrepresentable, after which no successful operation can advance that market.

### Likelihood Explanation
The attack requires extremely large balances—on the order of the protocol’s representable token ceiling—and a configured cap large enough to admit them. That makes the attack capital-intensive and unlikely for ordinary token supplies.

If a market is configured near the permitted domain ceiling, however, the attacker can deterministically create the condition without oracle manipulation, privileged access, leaked keys, or third-party contract misbehavior. They only need to:

1. Supply enough of the asset to create a large pool balance.
2. Supply sufficient collateral and borrow enough of the target asset to create scaled debt near the overflow threshold.
3. Wait for ordinary interest accrual to increase the debt index.
4. Invoke `update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, or another path that calls `global_sync`.

The borrow index only needs to grow until `borrowed_scaled_ray * borrow_index / RAY > i128::MAX`; reaching the protocol index ceiling is not required.

### Recommendation
Constrain persisted scaled supply and debt so that multiplication by the maximum possible index cannot overflow. For example, enforce a market-level invariant equivalent to:

```text
scaled_total <= i128::MAX * RAY / MAX_INDEX
```

The cap should be applied to both supply shares and debt shares, including revenue shares because revenue remains part of total supply. Alternatively, keep the full accrual computation in `I256`, detect an unrepresentable result before committing, and provide a bounded recovery path that permits debt reduction or socialized write-down without first evaluating the overflowing market value.

A regression test should deposit and borrow near the configured cap, advance the index until the valuation would exceed `i128::MAX`, and verify that withdrawal, repayment, liquidation, and index updates remain executable.

### Proof of Concept
Conceptual single-attacker sequence:

```rust
// Let `hub_asset` be a listed borrowable asset whose supply and borrow caps
// are close to `max_cap_for_decimals(asset_decimals)`.
//
// 1. Supply collateral in another listed market.
controller.supply(
    attacker_account,
    spoke_id,
    [(collateral_hub_asset, sufficient_collateral)],
);

// 2. Supply the target asset until total scaled supply is near i128::MAX.
controller.supply(
    attacker_account,
    spoke_id,
    [(target_hub_asset, near_supply_cap)],
);

// 3. Borrow a large fraction of that liquidity so that:
//    borrowed_scaled_ray * future_borrow_index / RAY > i128::MAX.
controller.borrow(
    attacker_account,
    spoke_id,
    [(target_hub_asset, large_borrow_amount)],
);

// 4. Wait until ordinary interest raises `borrow_index` enough that:
//    borrowed.mul(old_borrow_index)
// or:
//    borrowed.mul(new_borrow_index)
// exceeds i128::MAX.

// 5. Permissionlessly trigger accrual.
controller.update_indexes(target_hub_asset);

// Result: `Ray::mul` raises `MathOverflow`. The call commits no new index, so
// every later operation that invokes `global_sync` reaches the same product
// and reverts before users can withdraw, repay, liquidate, or clean bad debt.
```

The decisive overflow sites are the two index multiplications in `calculate_supplier_rewards`; the first can already overflow for sufficiently large existing debt. [6](#0-5)

### Citations

**File:** contracts/pool/src/interest.rs (L20-32)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** common/src/rates/index.rs (L11-18)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L73-84)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

```

**File:** common/src/math/fp.rs (L49-57)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }

    /// Divides this value by `other`, rounding the result half up.
    pub fn div(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, RAY, other.0))
    }
```

**File:** contracts/pool/src/cache/shares.rs (L14-28)
```rust
    /// Mints scaled supply shares into the market total.
    pub(crate) fn mint_supply(&mut self, scaled: Ray) {
        self.supplied = self.supplied.checked_add(&self.env, scaled);
    }

    /// Burns scaled supply shares, then asserts revenue ≤ total supply.
    pub(crate) fn burn_supply(&mut self, scaled: Ray) {
        self.supplied = self.supplied.checked_sub(&self.env, scaled);
        self.require_revenue_backed();
    }

    /// Mints scaled debt shares into the market total.
    pub(crate) fn mint_debt(&mut self, scaled: Ray) {
        self.borrowed = self.borrowed.checked_add(&self.env, scaled);
    }
```
