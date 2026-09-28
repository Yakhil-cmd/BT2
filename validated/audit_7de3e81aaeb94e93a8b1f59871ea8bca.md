### Title
Accrued RAY-domain value overflow in `scaled_to_original` permanently freezes an entire market (no withdraw, repay, or liquidation) — (File: common/src/rates/scaling.rs:14-16)

### Summary
XOXNO Lending stores supply/debt as RAY-scaled shares and every mutating pool entrypoint runs `interest::global_sync` before touching the position. Accrual begins by unscaling `borrowed` and `supplied` via `scaled_to_original` (`scaled * index / RAY`), whose I256 intermediate is converted back to `i128` by `to_i128` and panics with `MathOverflow` when the RAY-domain value exceeds `i128::MAX`. The index ceiling (`MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY = 1e36`) clamps the *index*, not the *value*, so on a whale-scale market the value overflows long before the index cap engages. Once crossed, the accrual panic is permanent: every subsequent `supply`, `withdraw`, `repay`, `seize_positions`, `claim_revenue`, `recapitalize`, and controller-routed `update_indexes`/`liquidate`/`clean_bad_debt` hits the same panic in `global_sync`, freezing all supplier cash and borrower collateral in that market forever.

### Finding Description
- `scaled_to_original` multiplies shares by index with no bound on the product: `scaled.mul(env, index)` → `mul_div_half_up` → `to_i128` panics on overflow [1](#0-0) [2](#0-1) 
- `accrue_step` calls `scaled_to_original` on `borrowed` and `supplied` at the top of every compounding chunk, before any index clamping can help [3](#0-2) 
- `global_sync` runs this accrue-first sequence on every market mutation [4](#0-3) ; the pool README confirms `Cache::load → interest::global_sync → mutate → guards` for every mutation [5](#0-4) 
- Withdraw itself is fine — `resolve_withdrawal` only overflows for the same reason via `unscale_supply` — but it never runs because `global_sync` panics first [6](#0-5) 
- `update_borrow_index` clamps the index at `1e36`, yet the pre-clamp product `supplied * supply_index` overflows `i128` when scaled shares exceed ~`i128::MAX / index`; at a 1e36-raw share total (≈1 billion whole 18-decimal tokens) the ceiling is reached at index ≈170×, far below the 1e9× index cap [7](#0-6) 
- `docs` and `INV-IDX-01` acknowledge "Debt-value overflow can still revert accrual before that ceiling is reached," but there is no mitigation — no saturating accrual, no ceiling alarm, no recovery entrypoint that skips `global_sync` [8](#0-7) 

### Impact Explanation
Permanent freezing of funds at market scope. Once `borrowed * borrow_index` or `supplied * supply_index` exceeds `i128::MAX` mid-accrual, the transaction always reverts inside `global_sync`, so suppliers can never withdraw, borrowers can never repay, liquidators cannot seize, and even `recapitalize` cannot execute — the entire market's cash and all associated collateral positions across spokes are irrecoverable. The in-repo test proves the freeze verbatim: after the cliff, `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW` and `borrow_index` remains below its cap [9](#0-8) 

### Likelihood Explanation
Reachable by a single unprivileged address with no privileged action: the whale calls controller `supply` of ~1 billion whole tokens into an 18-decimal market (or proportionally less for fewer-decimals assets — the cliff is scaled-shares × index, independent of token price) and `borrow` of ~98% of it against their own collateral in a second market, then simply waits. On the steep high-utilization segment of a configured curve (up to 200% APR, a valid `MarketParams`), the index compounds past ~170× within the tested horizon, after which the market is frozen. No oracle manipulation, no leaked keys, no admin cooperation required — the trigger is organic interest accrual on large legitimately-admitted positions, since caps only bound the token-to-RAY input conversion (`i128::MAX / 10^(27-d)`), not the accrued value [10](#0-9) . Likelihood is gated by capital requirements, but the docs themselves note "valid caps and bounded indexes do not guarantee that future accrual fits," so the condition is admitted by design parameters, not by an exploit edge case.

### Recommendation
Make accrual overflow-safe rather than relying on the value domain never being reached:

1. In `accrue_step`, compute `borrowed_original`/`supplied_original` with a saturating `I256` path (or clamp `scaled` to `i128::MAX * RAY / index` before multiplying) so a value over `i128::MAX` clamps utilization/rate instead of reverting.
2. Alternatively, cap `borrow_index` and `supply_index` growth dynamically at `i128::MAX / max(borrowed, supplied)` in `update_borrow_index`/`update_supply_index`, so the index stops accruing before the value overflows — mirroring how `MAX_BORROW_INDEX_RAY` already stops accrual, but at the real, earlier bound.
3. Add a mutation-free emergency path (e.g., a `seize`/`withdraw` flag that skips `global_sync` and uses stored indexes) so users can exit a market whose live accrual has already crossed the cliff.

### Proof of Concept
The repository ships a runnable PoC: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361` [11](#0-10) . It supplies `BILLION * 10^18` base units, borrows 98% of it, advances time year-by-year, and asserts that `update_indexes` begins failing with `MathOverflow`, that `borrow_index < MAX_BORROW_INDEX_RAY` (the intended cap never engaged), and that subsequent `withdraw` and `repay` calls revert with the same `MathOverflow` — the market is permanently frozen. The panic site is `to_i128` inside `mul_div_half_up`, reached from `scaled_to_original` at `common/src/rates/simulate.rs:60-61` during `global_sync`.

### Citations

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/math/fp_core.rs (L300-303)
```rust
fn to_i128(env: &Env, val: &I256) -> i128 {
    val.to_i128()
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/rates/simulate.rs (L51-69)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
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

**File:** contracts/pool/README.md (L161-168)
```markdown
```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```
```

**File:** docs/reference/formulas.md (L423-437)
```markdown
| Bound | Consequence |
|---|---|
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

**File:** docs/reference/invariants.md (L231-237)
```markdown
Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.

```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-361)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
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
