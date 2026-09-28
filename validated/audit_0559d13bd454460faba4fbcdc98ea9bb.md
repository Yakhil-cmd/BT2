### Title
Accrual `MathOverflow` panic at the RAY value ceiling permanently freezes all exits, repayments, and liquidations on a market - (File: common/src/rates/index.rs)

### Summary
CVE-2018-11499 is a crash-class bug (use-after-free in `handle_error()` → denial of service). The analog in XOXNO Lending is a reachable `panic_with_error!(GenericError::MathOverflow)` inside interest accrual. Because every mutating pool entrypoint runs `interest::global_sync` first, once a market's scaled balances × index cross the `i128` capacity, the accrual panics before any state can be written — and it panics on every subsequent call forever. All supplier funds, borrower repayments, and liquidation of underwater accounts in that market are permanently frozen, matching the "permanent freezing of funds" impact class.

### Finding Description
`Cache::load` → `interest::global_sync` runs `accrue_chunk` → `accrue_step` for every market touched by `update_indexes`, `supply`, `withdraw`, `repay`, `borrow`, `seize_positions`, `claim_revenue`, `recapitalize`, and `flash_loan` [1](#0-0) . Inside `accrue_step`, utilization and index growth are computed via `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)`, which multiply scaled RAY shares by a RAY index and panic with `MathOverflow` when the product exceeds `i128` capacity (`common/src/rates/index.rs`, exercised by the harness mirror at [2](#0-1) ).

The index cap `MAX_BORROW_INDEX_RAY` is meant to bound growth, but the value ceiling is hit first: a scaled book near the supply-cap saturation (`i128::MAX` scale) times an index ≈170× RAY overflows before the cap engages. The dedicated test proves the end state:

- `try_update_indexes` fails with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`.
- `try_withdraw` and `try_repay` fail with the same `MATH_OVERFLOW`, since both accrue first.
- Comment in the test: "the market is frozen: exits and repayments accrue first and hit the same panic" [3](#0-2) .

Once `borrow_index` has grown past the point where `borrowed * borrow_index` overflows, no amount of time-passage or parameter change shrinks the scaled balances or the monotonically non-decreasing `borrow_index` (`contracts/pool/README.md` notes `borrow_index` only ever grows), so the panic is irreversible. `recapitalize` also calls `Cache::load`/accrue, so even the recovery path is bricked.

### Impact Explanation
Permanent freezing of funds and protocol insolvency: every supplier's deposit in the affected market becomes unwithdrawable, borrowers cannot repay, and liquidators cannot seize underwater accounts — so bad debt accrues on top of the frozen book. Unlike a fail-closed guard (which is a design choice), this is an arithmetic cliff reachable through ordinary permissionless `supply`/`borrow`/`update_indexes` calls on a high-decimals market with lifted or large caps, exactly the "crash inside shared state advance" shape of the original CVE.

### Likelihood Explanation
An unprivileged attacker cannot force this quickly — it requires a whale-scale book (the test uses ~1 billion units of an 18-decimal token at 98% utilization) and sustained accrual over years, so it is a tail risk rather than an instant exploit, consistent with the CVE's "possible" remote crash. However, the trigger inputs (supply amount, borrow, waiting) are all permissionless actions any address can submit, the caps can be configured high enough by governance for legitimate markets, and there is no in-protocol escape hatch once crossed: `update_params` also accrues on the old curve first [4](#0-3) . Medium likelihood, permanent-frozen-funds impact → Medium/High severity. Note: `docs/reference/formulas.md#numeric-limits` acknowledges the cliff, so this may partially overlap a documented limitation — the report is still warranted because the failure mode is total and unrecoverable, not a bounded degradation.

### Recommendation
Clamp before multiplying: in `accrue_step`, cap `borrow_index` at `MAX_BORROW_INDEX_RAY` *before* `scaled_to_original` is evaluated, and evaluate `borrowed * borrow_index` via the widened `I256` path (as `compound_interest` already does for the exponent) with an explicit saturation rather than a panic, e.g., clamp the computed value to `i128::MAX`. Additionally, enforce a supply/borrow cap expressed in RAY value (`scaled_amount * index`) so that cap checks fail the entry instead of letting the book grow into the overflow cliff — the docs already warn caps must account for index growth; enforce it in `SpokeUsageContext::apply_entry`/`calculate_scaled_cap` rather than saturating to `i128::MAX` [5](#0-4) .

### Proof of Concept
The repository's own test is the PoC (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-362`):

```rust
// Market: BIG18 (18 decimals) on the steep segment of the XLM rate curve.
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);          // permissionless supply
t.borrow_raw(ALICE, "BIG18", principal * 98/100); // permissionless borrow
// advance_time in ~1-year steps; after a few years at 98% util:
//   t.try_update_indexes_for(&["BIG18"]) -> Err(MATH_OVERFLOW)
//   while borrow_index < MAX_BORROW_INDEX_RAY (cap never engaged)
// From then on, permanently:
//   t.try_withdraw_raw(BOB, "BIG18", 1)  -> MATH_OVERFLOW
//   t.try_repay(ALICE, "BIG18", 1.0)     -> MATH_OVERFLOW
```

Every verb accrues via `interest::global_sync` first, so once `scaled_to_original(borrowed, borrow_index)` overflows inside `accrue_step`, no state can ever be committed for that market again — funds are frozen forever.

### Citations

**File:** contracts/pool/src/interest.rs (L20-53)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
        env,
        cache.params(),
        cache.borrowed(),
        cache.supplied(),
        cache.borrow_index(),
        cache.supply_index(),
        delta_ms,
    );

    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
}
```

**File:** tests/fuzz/fuzz_targets/rates_and_index.rs (L294-313)
```rust
        let borrowed_original = scaled_to_original(env, borrowed, st.borrow_index);
        let supplied_original = scaled_to_original(env, st.supplied, st.supply_index);
        let util = utilization(env, borrowed_original, supplied_original);
        let borrow_rate = calculate_borrow_rate(env, util, params);
        let interest_factor = compound_interest(env, borrow_rate, chunk);

        let new_borrow_index = update_borrow_index(env, st.borrow_index, interest_factor);
        let (supplier_rewards, protocol_fee) =
            calculate_supplier_rewards(env, params, borrowed, new_borrow_index, st.borrow_index);

        let old_supply_index = st.supply_index;
        st.supply_index = update_supply_index(env, st.supplied, old_supply_index, supplier_rewards);
        let shortfall = supply_index_reward_shortfall(
            env,
            st.supplied,
            old_supply_index,
            st.supply_index,
            supplier_rewards,
        );
        st.borrow_index = new_borrow_index;
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
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
```

**File:** contracts/pool/README.md (L104-112)
```markdown
| `update_indexes` | `fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>)` | owner | Accrues each market to now, and writes only if time elapsed. |
| `supply` | `fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation>` | owner | Mints supply shares and credits cash, one mutation returned per entry. |
| `borrow` | `fn borrow(env: Env, receiver: Address, entries: Vec<PoolBorrowEntry>) -> Vec<PoolPositionMutation>` | owner | Mints debt shares, debits cash, and transfers the asset to `receiver`. |
| `withdraw` | `fn withdraw(env: Env, receiver: Address, is_liquidation: bool, entries: Vec<PoolWithdrawEntry>) -> Vec<PoolPositionMutation>` | owner | Burns supply shares and transfers the net amount to `receiver`. |
| `repay` | `fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation>` | owner | Burns debt shares, credits the net repay, and refunds overpayment to `payer`. |
| `net_settle` | `fn net_settle(env: Env, entry: PoolNetSettleEntry) -> PoolNetSettleResult` | owner | Offsets one user's supply against their own debt. Takes one entry, not a batch. |
| `seize_positions` | `fn seize_positions(env: Env, entries: Vec<PoolSeizeEntry>)` | owner | Writes off bad debt on the borrow side, or books a seized deposit as revenue. Returns nothing. |
| `flash_loan` | `fn flash_loan(env: Env, hub_asset: HubAssetKey, initiator: Address, receiver: Address, amount: i128, data: Bytes) -> i128` | owner | Pays out, calls `execute_flash_loan` on `receiver`, pulls principal plus fee back. Returns the fee. |
| `create_strategy` | `fn create_strategy(env: Env, receiver: Address, action: PoolAction, charge_fee: bool) -> PoolStrategyMutation` | owner | Mints debt, books the optional fee as revenue, and sends `amount - fee` to `receiver`. |
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
