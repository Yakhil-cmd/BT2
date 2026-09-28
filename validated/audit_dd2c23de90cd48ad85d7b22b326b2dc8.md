### Title
Permanent market freeze: `borrowed × borrow_index` overflows `i128` during accrual before the index cap engages - (File: common/src/rates/simulate.rs)

### Summary
`accrue_step` computes the total debt value as `borrowed * borrow_index / RAY` via `scaled_to_original` on every accrual chunk. The borrow-index cap `MAX_BORROW_INDEX_RAY` bounds only the index, not the `borrowed × index` product. On a market holding a very large total borrow (reachable for high-supply, high-decimal tokens such as memecoins), the product overflows `i128` at a borrow index of roughly 170× RAY — well below the `10^36` index cap — and panics with `MathOverflow`. Because every mutating pool verb runs `global_sync` → `accrue_chunk` → `accrue_step` before touching state, the panic bricks the market permanently: no repay, withdraw, supply, borrow, liquidation, `clean_bad_debt`, or `update_indexes` succeeds, and `flash_loan`/`flash_position`/`multiply`/`swap_*` routes die the same way. All supplier funds and unclaimed yield in that market are frozen forever. This is the on-chain analog of CVE-2024-36616's integer-overflow denial of service.

### Finding Description
`accrue_step` first unscales the scaled debt:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
```

`scaled_to_original` is `scaled.mul(env, index)` — `mul_div_half_up` with a `d = RAY` denominator and an `I256`-widened intermediate (`common/src/math/fp_core.rs:122-143`). The widening only protects the *intermediate* product; the final result must still fit `i128`, otherwise `to_i128()` returns `None` and the call panics with `GenericError::MathOverflow`. The overflow condition is `borrowed_ray × borrow_index / RAY > i128::MAX ≈ 1.7×10^38`.

The only bound on this domain is the index cap in `update_borrow_index` (`common/src/rates/index.rs:13-19`), which clamps `borrow_index ≤ MAX_BORROW_INDEX_RAY = 10^36` — but the clamp is applied *after* the value computation at `simulate.rs:60`, so it cannot prevent the product overflow. For a market holding `B` borrowed tokens with `d` decimals, `borrowed_ray = B × 10^(27−d)`, and the freeze triggers when `borrow_index ≳ i128::MAX × RAY / borrowed_ray`. With `B = 10^27` units of an 18-decimal asset (`borrowed_ray = 10^36`), that threshold is only ≈ 170× RAY — the borrow index crosses it in a few years at high utilization on a steep rate curve, as demonstrated by the in-repo test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`), which asserts `MATH_OVERFLOW` on `update_indexes`, `withdraw`, and `repay` alike.

Once the stored `borrowed` and `borrow_index` satisfy the overflow condition, the panic is permanent and unconditional: `global_sync` (`contracts/pool/src/interest.rs:20-33`) runs at the head of every cache-loading op, and `Cache::calculate_utilization` (`contracts/pool/src/cache/scale.rs:19-27`) hits the same `scaled_to_original` overflow even if accrual were skipped. Nothing an unprivileged user — or anyone — can call will reduce `borrowed` or `borrow_index`, because reducing them requires a successful transaction, and every transaction panics first.

### Impact Explanation
Permanent freezing of all user funds in the affected market. Suppliers cannot withdraw (`withdraw` accrues first), borrowers cannot repay, liquidations cannot execute, bad debt cannot be cleaned, and accrued/unclaimed supplier yield and protocol revenue are locked. Positions referencing the market in the controller are frozen as well, since controller entrypoints load the market's cache. The condition is irreversible once crossed.

### Likelihood Explanation
The trigger requires a total borrowed value whose RAY-normalized amount is large enough that `borrowed_ray × ~170×RAY / RAY > i128::MAX`, i.e. `borrowed_ray ≳ 10^36`. For a 7-decimal asset that is ~10^16 tokens — implausible. For an 18-decimal token with quadrillion-scale supply (a typical memecoin listing), `10^27` tokens is a fraction of circulating supply and can be accumulated by a single whale or reached organically over years of accrual at high utilization. Borrow/supply caps gate the accumulation, but `calculate_scaled_cap` (`common/src/rates/scaling.rs:26-33`) *saturates* at `i128::MAX` rather than rejecting oversized caps, so a generously capped market does not block the condition. The attack path is fully unprivileged: `supply` + `borrow` (or simply waiting for organic accrual on a populated market), then any call to `update_indexes` — itself a permissionless keeper entrypoint — triggers the freeze. Severity is Medium: the impact is a permanent freeze of all market funds, but reaching the domain requires either a large-supply-asset market at scale or sustained years-long accrual.

### Recommendation
Make the accrual overflow-impossible rather than panicking:

1. In `accrue_step`, saturate `scaled_to_original` for the utilization input (`mul_div_floor_saturating` already exists in `fp_core` and is used by `update_supply_index`/`protocol_fee_shares`) — utilization is already capped by `MAX_UTILIZATION` semantics downstream, so saturating the debt valuation cannot distort the rate.
2. Clamp the borrow index earlier and lower: cap `borrow_index` at `i128::MAX × RAY / borrowed_ray.max(1)` (a per-market dynamic bound) inside `update_borrow_index`, so the product can never exceed `i128` regardless of `borrowed`.
3. Apply the same guard to `supplied × supply_index` in `accrue_step` (`simulate.rs:61`) and `Cache::calculate_utilization`, which share the identical overflow shape.
4. Alternatively, cap `calculate_scaled_borrow`/`calculate_scaled_supply` minted shares so `scaled × MAX_INDEX / RAY` stays within `i128` for the configured cap domain — enforcing the headroom the index cap assumes but does not check.

### Proof of Concept
Reachable state (already exercised by the repo's own harness):

1. A market is listed for an 18-decimal asset with borrow/supply caps above `10^27` units (caps saturate open at `i128::MAX`, so large caps do not constrain).
2. Attacker (or organic flow) supplies `10^27` units and borrows ~98% of it: `borrowed_ray ≈ 9.8×10^35`.
3. At a steep-curve utilization, `update_borrow_index` compounds the index past `i128::MAX × RAY / borrowed_ray ≈ 1.7×10^29 ≈ 170×RAY` — reached in a few simulated years (`large_positions_and_long_horizons.rs:335-346`), faster at sustained `MAX_BORROW_RATE_RAY`.
4. Anyone calls permissionless `update_indexes` (or `supply`/`borrow`/`withdraw`/`repay`/`liquidate`/`clean_bad_debt`/`flash_loan`/`flash_position`/`multiply`/`swap_debt`/`swap_collateral`/`repay_debt_with_collateral`/`migrate_from_blend`/`claim_revenue`/`recapitalize`). `global_sync` → `accrue_step` → `scaled_to_original(borrowed, borrow_index)` computes `borrowed × index / RAY > i128::MAX`; `I256::to_i128()` yields `None` and `mul_div_half_up` panics `MathOverflow`.
5. Every subsequent call hits the same panic — the harness asserts exactly this: `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all fail with `errors::MATH_OVERFLOW` (`large_positions_and_long_horizons.rs:343-356`), and `last.borrow_index < MAX_BORROW_INDEX_RAY`, proving the cap never engaged. The market's funds are permanently frozen.

Key citations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
```

**File:** common/src/math/fp_core.rs (L122-143)
```rust
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
    }
    let half = d / 2;

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

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-361)
```rust
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
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
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
}
```
