### Title
Accrual RAY-value overflow permanently freezes all funds in a saturated market - (File: contracts/pool/src/interest.rs)

### Summary
The NULL-deref crash class maps onto XOXNO Lending as an unconditional arithmetic panic inside market interest accrual: once the ceiled debt value `borrowed_scaled * borrow_index` exceeds the `i128`/RAY domain, `interest::global_sync` panics with `MathOverflow` before any mutation. Because every market entrypoint (`borrow`, `withdraw`, `repay`, `seize_positions`, `flash_loan`, `claim_revenue`, `recapitalize`, `update_indexes`) begins with `ops::synced_market → global_sync`, the panic bricks the market permanently: no user can repay, withdraw, be liquidated, or recapitalize, and even the permissionless `update_indexes` keeper call reverts so the index can never be pushed to its `MAX_BORROW_INDEX_RAY` cap to halt further accrual.

### Finding Description
The panic chain is: controller verb → pool owner-gated entrypoint → `ops::synced_market` (`contracts/pool/src/ops/mod.rs:30-34`) → `interest::global_sync` → scaled-to-value multiplication in `common/src/rates/index.rs` / `common/src/math/fp.rs` (`Ray::mul`, `mul_div_floor` in `common/src/math/fp_core.rs:148-159`), which panics with `GenericError::MathOverflow` when the product does not fit `i128`. An unprivileged attacker constructs this state by supplying the maximum cap amount of a high-decimals (18) asset and borrowing ~98% of it (`supply`/`borrow` are open to anyone). Time then does the rest: at the steep segment of a 200%-APR-capable curve, a few years of chunked accrual grows `borrow_index × borrowed` past `i128::MAX` while the index itself is still far below `MAX_BORROW_INDEX_RAY`. The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-360`) proves the cliff: `update_indexes`, `withdraw`, and `repay` all revert with `MathOverflow`, and `last.borrow_index < MAX_BORROW_INDEX_RAY`, i.e., the saturation cap that would end accrual is unreachable because the accrual arithmetic itself traps first.

### Impact Explanation
Every supplier's tokens in that market are permanently frozen — `withdraw` panics during the pre-accrual that precedes any share burn. The borrower's debt can never be repaid, liquidated, or written off (`seize_positions` also accrues first), so no recovery path exists; `recapitalize` cannot help because it too syncs the market. This is exactly the "crafted input → crash → denial of service" analog of CVE-2018-13457, but with on-chain permanence rather than process restart: one unprivileged actor can create a market state that permanently destroys access to all funds deposited in it, i.e., de facto loss of user funds.

### Likelihood Explanation
Likelihood is bounded by capital requirements: the attack needs on the order of `10^11` whole tokens supplied to an 18-decimals market with caps lifted by governance to `max_cap_for_decimals`, plus multi-year sustained high utilization (or a market parameter set with a steep high-utilization curve segment). Caps set conservatively below the RAY domain make the overflow unreachable; caps admitted near `i128::MAX / 10^(27-d)` make it reachable. No privileged action, oracle manipulation, or reentrancy is required — only `supply`, `borrow`, and waiting.

### Recommendation
Saturate rather than panic during accrual: in `interest::global_sync` and the index/value multiplication, clamp the debt value and index at `MAX_BORROW_INDEX_RAY` (and stop accruing once the value bound is hit) instead of letting `mul_div_*` trap, so exits remain callable. Alternatively, validate at `supply`/`borrow` entry that `borrowed × projected_max_index` stays within the RAY domain — i.e., derive the cap from the accrual ceiling rather than from the token-width alone. Emit an event before the index nears the cliff so the market can be drained or wound down first.

### Proof of Concept
Encoded as the repository's own regression test (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`):

1. `supply(BOB, "BIG18", 1_000_000_000 * 10^18)` — maximum admitted amount on an 18-decimal market with caps lifted.
2. `borrow(ALICE, "BIG18", 0.98 * principal)` after supplying large collateral — all calls unprivileged.
3. Advance ledger time in yearly chunks calling `update_indexes`.
4. After a few years at ~98% utilization on a steep curve, `try_update_indexes_for(["BIG18"])` fails with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`.
5. Thereafter `try_withdraw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` both revert with `MathOverflow` — permanently.

Confidence caveat: this behavior is already described in `docs/reference/formulas.md:432-437` ("value overflow can ... block repayment/withdrawal"), which frames it as a documented arithmetic limit. If the program's triage treats documented limits as out of scope per the reject rules, this finding should be downgraded; the mechanics, entrypoints, and irreversibility are nevertheless verified in code and tests. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-360)
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
```

**File:** contracts/pool/src/ops/mod.rs (L29-40)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
}
```

**File:** common/src/math/fp_core.rs (L148-159)
```rust
pub fn mul_div_floor(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    let nonneg = quotient_is_nonnegative(x, y, d);
    to_i128(env, &div_floor_i256(env, &x256.mul(&y256), &d256, nonneg))
}
```

**File:** docs/reference/formulas.md (L429-437)
```markdown
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
