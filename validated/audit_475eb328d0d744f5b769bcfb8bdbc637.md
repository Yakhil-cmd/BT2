### Title
Sustained high-utilization whale market overflow permanently freezes repayment and withdrawals - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary
An unprivileged actor can open one account supplying an extremely large 18-decimal asset and a second account borrowing it at sustained high utilization. After the borrow index grows enough, accrual multiplies the scaled debt by the index in `calculate_supplier_rewards`, exceeding `i128::MAX` before the borrow-index cap is reached. Once this state is reached, every operation that accrues the market fails with `MathOverflow`, including `repay`, `withdraw`, and liquidation, permanently freezing the market absent an upgrade or state correction. [1](#0-0) [2](#0-1) 

### Finding Description
`global_sync` runs before market mutations and calls `accrue_chunk`, which delegates the borrow-index and interest accounting to `accrue_step`. [3](#0-2)  The vulnerable calculation converts both old and new scaled debt into RAY-denominated value with `borrowed.mul(env, old_borrow_index)` and `borrowed.mul(env, new_borrow_index)`. [4](#0-3)  Although `update_borrow_index` caps the stored index at `MAX_BORROW_INDEX_RAY`, that cap is applied only after multiplying the old index by the interest factor, and it does not prevent `borrowed * new_borrow_index` from overflowing `i128` first. [5](#0-4) 

The protocol exposes the needed state transitions to ordinary users: `supply` with `account_id = 0` creates an account owned by the caller, and `borrow` draws funds against that account subject to solvency. [6](#0-5) [7](#0-6)  A single actor can therefore use separate self-owned accounts for the supplying leg and the borrowing leg; no owner, keeper, governance role, oracle manipulation, callback, or compromised key is required. [8](#0-7) 

The repository has a deterministic regression test proving the cliff: a one-billion-token, 18-decimal market at 98% utilization reaches an index above the value ceiling before reaching `MAX_BORROW_INDEX_RAY`; afterward, `update_indexes`, `withdraw`, and `repay` all fail with `MathOverflow`. [2](#0-1)  The repayment and withdrawal implementations both load a synced market leg before performing their mutation, so they cannot bypass the overflowing accrual. [9](#0-8) [10](#0-9) 

### Impact Explanation
This permanently freezes all funds and debt operations for the affected `(hub_id, asset)` market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot complete the pool legs needed by `liquidate`, and `clean_bad_debt` cannot clear positions in that market once the overflowed accrual is unavoidable. [2](#0-1)  The issue affects more than the attacker because all users holding supply or debt shares in the same hub asset share one market book. [11](#0-10) 

### Likelihood Explanation
Likelihood is medium because the attacker needs enough capital to create and maintain a very large high-utilization market over an extended accrual period, and the relevant market caps or listing configuration must admit that exposure. [12](#0-11)  No privileged call is part of the exploit path; the actor supplies liquidity on one self-owned account, borrows from another, and lets ledger time advance until the next accrual overflows. [8](#0-7) 

### Recommendation
Cap or check the product `borrowed * borrow_index` before allowing a market to approach the `i128` value ceiling. In particular:

- Reject new supply or borrow that would make `borrowed` exceed a configured safe scaled-debt bound based on the maximum possible index.
- Before applying a new borrow index, calculate debt value with an explicit overflow-safe check and fail entry before the unsafe state is created.
- Add an accrual recovery path that can clamp the borrow index or disable further accrual without first evaluating `borrowed * index`.
- Extend the existing regression test to verify that caps prevent reaching the overflow rather than merely documenting the freeze. [2](#0-1) 

### Proof of Concept
The repository already contains the applicable deterministic PoC, `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [13](#0-12) 

1. Deploy a market for an 18-decimal asset and another collateral market, with caps and utilization configured to admit the PoC exposure. [14](#0-13) 
2. As one unprivileged actor, call `supply(caller, 0, spoke_id, [(BIG18, principal)])` to create the liquidity account, where `principal = 1_000_000_000 * 10^18`. [15](#0-14) 
3. Create a second self-owned account with sufficient `COL` collateral and call `borrow(caller, borrower_account_id, [(BIG18, principal * 98 / 100)], None)`. [16](#0-15) 
4. Allow ledger time to advance in one-year intervals and optionally call the permissionless `update_indexes(caller, [BIG18])` after each interval. [17](#0-16) 
5. The next accrual eventually fails with `MathOverflow` while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [18](#0-17) 
6. Subsequent `withdraw` and `repay` calls against the same market fail with the same `MathOverflow`, demonstrating that ordinary exit and repair paths are frozen. [19](#0-18)

### Citations

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L73-88)
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

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-356)
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
```

**File:** contracts/pool/src/interest.rs (L20-52)
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
```

**File:** contracts/controller/README.md (L31-39)
```markdown
  `caller`, `liquidator` or `payer` argument. `borrow`, `withdraw` and every
  strategy entrypoint except `flash_loan` also require the caller to be the
  account owner or an active delegate that the owner added. Several position
  entrypoints are permissionless instead: anyone may `repay` any account's
  debt, `liquidate` an account whose health factor is below one (including the
  account's own owner), and `clean_bad_debt` on an insolvent account once its
  remaining collateral is at or below the dust threshold. A third-party
  `supply` may only top up hub assets the account already holds a supply
  position in; an `account_id` of 0 creates a new account owned by the caller.
```

**File:** contracts/controller/README.md (L73-76)
```markdown
| `supply` | `fn supply( env: Env, caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>, ) -> u64` | blocked by global pause | Supplies `assets` as collateral to `account_id` in spoke `spoke_id`, creating a new account when `account_id` is 0, and returns the account id. |
| `borrow` | `fn borrow( env: Env, caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>, )` | blocked by global pause | Borrows `borrows` against `account_id`'s collateral, sending the funds to `to` if provided or to the caller otherwise; reverts if the resulting position breaches the account's solvency limits. |
| `withdraw` | `fn withdraw( env: Env, caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>, ) -> Vec<(HubAssetKey, i128)>` | — | Withdraws `withdrawals` from `account_id`'s supplied collateral, sending the funds to `to` if provided or to the caller otherwise, and returns the amounts actually withdrawn; a zero amount for an asset withdraws the entire position. |
| `repay` | `fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | — | Repays `payments` against `account_id`'s debt positions, pulling the funds from the caller and refunding any excess. |
```

**File:** scripts/permissionless_entrypoints.txt (L69-77)
```text
controller::supply | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may top up an account they do not own, but only for hub assets it already holds a supply position in; a caller that is neither the owner nor an active delegate cannot open a new asset slot, and account_id 0 creates an account owned by the caller.
controller::repay | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may repay any account's debt. Funds are pulled from the caller's own balance and credited from the measured receipt; the target's liabilities can only fall.
controller::liquidate | caller-auth | INV-AUTH-03, INV-LIQ-01, INV-LIQ-02 | Anyone may liquidate an account whose health factor is below one, including the account's own owner; in Credit seize mode the receiving account must be a different account that the liquidator owns or is an active delegate of, and seizure stays coupled to the debt actually repaid.
controller::clean_bad_debt | caller-auth | INV-AUTH-03, INV-LIQ-04 | Anyone may socialize an insolvent account's residual debt, but only once its remaining collateral is at or below the dust threshold; only the owner-gated force_socialize_bad_debt omits the dust cap.
controller::recapitalize | caller-auth | INV-AUTH-03, INV-ACCT-02, INV-ACCT-03 | Anyone may donate their own funds to cover a market's backing shortfall; only the measured receipt up to the shortfall is applied and the excess is refunded to the payer.
controller::update_indexes | caller-auth | INV-AUTH-03, INV-IDX-04 | Keeper maintenance: accrues interest to the current ledger timestamp. Accrual never lowers the borrow or supply index and each chunk's rate is capped at max_borrow_rate, so the caller chooses only the accrual timing and cannot lower anyone's balance.
controller::claim_revenue | caller-auth | INV-AUTH-03, INV-ACCT-06 | Keeper maintenance: sweeps accrued protocol revenue to the governance-configured accumulator. The caller picks the timing, never the recipient.
controller::update_account_threshold | caller-auth | INV-AUTH-03, INV-RISK-01 | Keeper maintenance: restamps cached risk parameters to their currently listed values. Without has_risks it restamps LTV only, which the health factor does not read; with has_risks set it reverts unless the account clears the update health-factor floor, so it cannot be used to push an account into liquidation.
controller::flash_loan | caller-auth | INV-AUTH-03, INV-FLASH-01, INV-FLASH-02 | Anyone may borrow within a single call; the pool verifies principal plus fee is back before returning, and the flash-loan flag blocks monetary reentrancy into position flows.
```

**File:** contracts/pool/src/ops/repay.rs (L40-59)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);

    let snapshot = cache.commit();
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-81)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

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

    let snapshot = cache.commit();
```

**File:** docs/explanation/decisions.md (L91-94)
```markdown
and revenue. One pool provides custody for all markets. Markets for one token
in different hubs keep distinct books but share its pool balance and token
risks. Spokes that list the same hub asset share its single market book.

```
