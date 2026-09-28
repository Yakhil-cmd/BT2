### Title
Checked RAY-value overflow permanently freezes an oversized market’s exits - (File: common/src/rates/simulate.rs)

### Summary
`accrue_step` computes `borrowed * borrow_index` and `supplied * supply_index` through `scaled_to_original`, which panics when the resulting RAY value cannot fit in `i128`. [1](#0-0) [2](#0-1) [3](#0-2) 

Because every mutation of an existing market performs `global_sync` before applying the requested operation, reaching this numeric boundary makes subsequent index updates, withdrawals, repayments, liquidations, and recapitalization calls fail before their state transition executes. [4](#0-3) [5](#0-4) 

### Finding Description
The interest path first converts scaled debt and supply back into RAY-denominated asset values using `scaled.mul(env, index)`. [1](#0-0) [2](#0-1) 

`Ray::mul` ultimately calls `mul_div_half_up`; if even the widened `I256` result cannot convert back to `i128`, the function panics with `MathOverflow`. [6](#0-5) 

The borrow-index ceiling does not prevent this condition because `update_borrow_index` performs the multiplication before comparing the result with `MAX_BORROW_INDEX_RAY`, and the separate scaled-position multiplication can overflow even while the index remains below that ceiling. [7](#0-6) 

An unprivileged user can approach the boundary through ordinary `supply` and `borrow` calls, while anyone can trigger the failing accrual with `update_indexes(caller, assets)`. [8](#0-7) [9](#0-8) 

The in-repository harness demonstrates this exact behavior with a one-billion-token, 18-decimal market and a 98%-of-principal borrow: `update_indexes` eventually returns `MathOverflow`, after which both withdrawal and repayment also fail. [10](#0-9) 

### Impact Explanation
Once the market state enters the unrepresentable RAY-value range, user collateral and pool liquidity are permanently frozen unless a privileged upgrade or migration changes the arithmetic path. [4](#0-3) 

Borrowers cannot repay, suppliers cannot withdraw, liquidators cannot reduce bad debt, and recapitalization cannot rescue the market because `recapitalize` also loads and synchronizes the market before crediting cash. [11](#0-10) 

This satisfies the permanent-freezing impact class rather than being a transient input-validation failure. [12](#0-11) 

### Likelihood Explanation
Exploitation requires a market whose configured caps and liquidity admit extremely large scaled positions, followed by enough borrow-index growth for `scaled_amount * index` to exceed `i128::MAX`. [13](#0-12) 

The attacker does not need a privileged call, leaked key, oracle manipulation, or malformed token behavior; they can use their own supply and borrow positions and permissionless `update_indexes` calls. [8](#0-7) [9](#0-8) 

The substantial capital requirement and dependence on admitted market size make exploitation difficult, but the resulting failure is deterministic once the arithmetic boundary is reached. [10](#0-9) 

### Recommendation
Enforce supply and borrow caps against projected RAY-value headroom, not only token-unit limits, so entries cannot create a state whose next accrual overflows. [14](#0-13) 

Before updating `supplied`, `borrowed`, or either index, calculate the maximum post-operation scaled value that remains convertible by `scaled_to_original`, and reject or clamp growth below that boundary. [1](#0-0) [7](#0-6) 

Add a non-accruing settlement or recovery mode for markets that reach the numeric boundary so withdrawals, repayments, liquidation, and recapitalization remain possible without re-entering the overflowing calculation. [5](#0-4) 

### Proof of Concept
Use an 18-decimal market whose supply and borrow caps admit a `1_000_000_000 * 10^18`-unit deposit. [15](#0-14) 

Call `supply(alice, 0, spoke_id, [(BIG18, 1_000_000_000 * 10^18)])`, then create or use another account owned by `alice`, supply sufficient collateral, and call `borrow(alice, account_id, [(BIG18, 980_000_000 * 10^18)], None)`. [8](#0-7) [16](#0-15) 

Advance the ledger and call `update_indexes(alice, [BIG18])`; once the scaled debt multiplied by the borrow index exceeds `i128::MAX`, the call fails with `MathOverflow`. [17](#0-16) [18](#0-17) 

Subsequent `withdraw` and `repay` calls fail at the same synchronization step, as demonstrated by the existing regression test. [5](#0-4) [19](#0-18)

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp_core.rs (L128-143)
```rust
    // Fast path: the biased product fits `i128`, so the whole computation is
    // native. `x * y + half` is non-negative here, so `/` is the floor the
    // widened path would produce.
    if let Some(biased) = x
        .checked_mul(y)
        .and_then(|product| product.checked_add(half))
    {
        return Some(biased / d);
    }

    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/pool/README.md (L159-167)
```markdown
Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```

**File:** contracts/pool/src/interest.rs (L20-33)
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
}
```

**File:** common/src/rates/index.rs (L13-19)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** contracts/controller/src/lib.rs (L93-115)
```rust
    #[when_not_paused]
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-357)
```rust
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
    std::println!(
```

**File:** contracts/pool/src/ops/recapitalize.rs (L49-58)
```rust
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```

**File:** docs/reference/formulas.md (L405-417)
```markdown
## Caps, fees, and numeric limits

A cap is in native token units. Entry compares stored scaled usage plus the
new scaled amount with the cap floor-converted at the current index. Zero cap
allows no positive exposure. Exits subtract usage without checking caps;
missing usage rows and zero exit deltas are no-ops. Cap→scaled conversion
saturates at `i128::MAX` (`calculate_scaled_cap`), so the entry check fails
open instead of trapping. A saturated scaled cap does not enforce the
configured asset-unit limit. An admitted cap saturates only at an index below
one RAY. Only a bad-debt write-down moves the supply index below one RAY; at
its floor (`RAY / 1000`), a supply cap above 1/1000 of the admitted maximum
saturates. The borrow index never falls below one RAY, so an admitted borrow
cap cannot saturate. Position conversion still rejects overflow.
```

**File:** docs/reference/formulas.md (L425-437)
```markdown
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
