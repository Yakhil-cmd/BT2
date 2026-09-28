### Title
Permissionless liquidation-curve execution can abruptly increase seized collateral - ([File: contracts/controller/src/config/spoke.rs](contracts/controller/src/config/spoke.rs))

### Summary
A ready `SetSpokeLiquidationCurve` governance operation can be executed by any address and changes the spoke-wide liquidation curve immediately. Because the curve is read live during liquidation rather than stamped on each position, an attacker can execute a curve update that raises the effective bonus and immediately liquidate an already-underwater account under the new economics. The victim loses more collateral than under the curve in effect when the liquidation opportunity arose. [1](#0-0) 

### Finding Description
`Governance::execute` permits `executor = None`, meaning any address may execute a ready scheduled operation. [2](#0-1)  For `AdminOperation::SetSpokeLiquidationCurve`, governance invokes controller `set_spoke_liquidation_curve` with `(spoke_id, target_hf_wad, hf_for_max_bonus_wad, liquidation_bonus_factor_bps)`. [3](#0-2) 

The controller validates the tuple and directly overwrites the stored spoke curve, without checking whether existing accounts’ liquidation quotes remain unchanged or staging the update per account. [4](#0-3)  Unlike the stamped per-position liquidation threshold and base bonus, the curve is shared spoke state and is applied to all existing accounts. [5](#0-4) 

During liquidation, `LiquidationCurve::from_config` reads the live `target_hf`, `hf_for_max_bonus`, and `bonus_factor`. [6](#0-5)  The resulting scaled bonus is used to calculate the repayment target and seizure economics. [7](#0-6) 

### Impact Explanation
An unprivileged liquidator can arrange execution of a ready curve change immediately before `Controller::liquidate`, causing the victim’s collateral seizure to be priced with the new curve rather than the curve that was active when the account became liquidatable. A higher target, lower max-bonus knee, or larger bonus factor can increase the bonus component and therefore the collateral received for the same debt payment. [8](#0-7) 

This is a loss of user collateral beyond the liquidation terms that existed immediately before the state transition. The issue is most relevant when a scheduled operation increases the effective bonus while one or more accounts in that spoke are already liquidatable.

### Likelihood Explanation
The attack requires a governance operation that raises the liquidation economics to reach its ready state and at least one liquidatable account in the affected spoke. The executor requires no role when `executor` is `None`, so any liquidation bot can monitor ready operations and execute the configuration change itself. [9](#0-8) 

Likelihood is conditional rather than continuously present because the operation must already be scheduled and become executable. However, the delay announces the change in advance, giving MEV participants time to prepare liquidations for the first block in which it is ready.

### Recommendation
Make liquidation-curve changes non-abrupt for existing risk states. For example, stamp the curve or resulting liquidation parameters on each position and refresh them through the existing gated threshold-update path, or record an activation ledger and apply the new curve only to liquidation opportunities that arise after a configured grace period.

Alternatively, reject a curve update while any account in the spoke is currently liquidatable and would receive a higher bonus under the new curve. That is stricter, but prevents the execution transaction itself from changing the economics of an existing liquidation.

### Proof of Concept
1. Governance schedules `AdminOperation::SetSpokeLiquidationCurve` for spoke `S`, changing the curve so that a liquidation at victim HF `h < 1` receives a larger bonus.
2. The operation reaches `Ready`.
3. An attacker calls:

   ```text
   Governance::execute(
       executor = None,
       target = controller,
       function = "set_spoke_liquidation_curve",
       args = [S, new_target_hf_wad, new_hf_for_max_bonus_wad, new_factor_bps],
       predecessor = 0x00..00,
       salt = scheduled_salt,
   )
   ```

4. The controller immediately stores the new spoke curve. [10](#0-9) 
5. The attacker then calls:

   ```text
   Controller::liquidate(
       liquidator = attacker,
       account_id = victim,
       debt_payments = [(debt_hub_asset, planned_payment)],
       seize_mode = SeizeMode::Transfer,
   )
   ```

6. Liquidation constructs `LiquidationCurve` from the newly stored spoke values and uses the increased scaled bonus in `estimate_liquidation_amount`. [6](#0-5) [11](#0-10) 
7. The attacker receives more collateral than the same liquidation would have delivered before the governance execution.

### Citations

**File:** contracts/controller/src/config/spoke.rs (L51-75)
```rust
/// Validates, stores, and emits the spoke's liquidation curve parameters.
pub(crate) fn set_spoke_liquidation_curve(
    env: &Env,
    id: u32,
    target_hf_wad: i128,
    hf_for_max_bonus_wad: i128,
    liquidation_bonus_factor_bps: u32,
) {
    validate_liquidation_curve(
        env,
        target_hf_wad,
        hf_for_max_bonus_wad,
        liquidation_bonus_factor_bps,
    );

    let mut spoke = storage::get_spoke(env, id);
    spoke.liquidation_target_hf_wad = target_hf_wad;
    spoke.hf_for_max_bonus_wad = hf_for_max_bonus_wad;
    spoke.liquidation_bonus_factor_bps = liquidation_bonus_factor_bps;
    storage::set_spoke(env, id, &spoke);

    UpdateSpokeEvent {
        spoke: EventSpoke::new(id, &spoke),
    }
    .publish(env);
```

**File:** contracts/governance/src/api.rs (L53-66)
```rust
    /// Executes a ready, non-expired scheduled op against `target` (not this
    /// contract). If `executor` is `Some`, requires that address to auth and
    /// hold `EXECUTOR_ROLE`; if `None`, no executor role check (anyone may
    /// drive execution of a ready op). Clears scheduled state on success.
    fn execute(
        env: Env,
        executor: Option<Address>,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
    ) -> Val {
        lifecycle::execute(&env, executor, target, function, args, predecessor, salt)
```

**File:** contracts/governance/src/op.rs (L412-429)
```rust
        AdminOperation::SetSpokeLiquidationCurve(args) => {
            validate_liquidation_curve(
                env,
                args.target_hf_wad,
                args.hf_for_max_bonus_wad,
                args.liquidation_bonus_factor_bps,
            );
            controller_operation(
                env,
                "set_spoke_liquidation_curve",
                vec![
                    env,
                    args.spoke_id.into_val(env),
                    args.target_hf_wad.into_val(env),
                    args.hf_for_max_bonus_wad.into_val(env),
                    args.liquidation_bonus_factor_bps.into_val(env),
                ],
            )
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L361-374)
```markdown

Each supply position stores its own LTV, LT, base bonus and liquidation fee.
It copies them from the spoke listing when it is created
(`get_or_create_supply_position`). After that, the controller uses the
stored values, not the live listing:

- HF uses the stored LT (`calculate_account_risk_totals`).
- The borrow limit uses the lower of the stored LTV and the stored LT.
- The base bonus `b0` is the USD-weighted stored bonus. The maximum bonus `M`
  comes from the stored LT. The fee is the stored fee
  (`get_account_bonus_params`).
- The curve (`H`, `K`, `f`) is not stored. Each liquidation reads it from the
  spoke. `configureSpokeCurves` changes it for all accounts of the spoke at
  the same time.
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L35-55)
```rust
impl LiquidationCurve {
    pub(crate) fn from_config(cfg: &SpokeConfig) -> Self {
        Self {
            target_hf: Wad::from(cfg.liquidation_target_hf_wad),
            hf_for_max_bonus: Wad::from(cfg.hf_for_max_bonus_wad),
            bonus_factor: Bps::from(i128::from(cfg.liquidation_bonus_factor_bps)),
        }
    }

    /// Ramps from zero at `target` to one WAD at the max-bonus threshold.
    /// Degenerate or reversed threshold ranges return one WAD.
    fn bonus_scale(&self, env: &Env, hf: Wad, target: Wad) -> Wad {
        if target <= self.hf_for_max_bonus {
            Wad::ONE
        } else {
            target
                .checked_sub(env, hf)
                .div(env, target.checked_sub(env, self.hf_for_max_bonus))
                .min(Wad::ONE)
        }
    }
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L58-80)
```rust
/// Interpolates the base-to-max bonus increment as HF falls, then applies the
/// configured factor. HF at or above `target` receives the base bonus.
pub(crate) fn calculate_linear_bonus_with_target(
    env: &Env,
    hf: Wad,
    base: Bps,
    max: Bps,
    curve: &LiquidationCurve,
    target: Wad,
) -> Bps {
    if hf >= target {
        return base;
    }
    let scale = curve.bonus_scale(env, hf, target);

    let bonus_range = max.checked_sub(env, base);
    let bonus_increment = Wad::from(bonus_range.raw()).mul(env, scale).raw();
    let scaled_increment = curve.bonus_factor.apply_to(env, bonus_increment);
    Bps::from(
        base.raw()
            .checked_add(scaled_increment)
            .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow)),
    )
```

**File:** contracts/controller/src/positions/liquidation/curve.rs (L102-137)
```rust
pub(crate) fn estimate_liquidation_amount(
    env: &Env,
    snap: &LiquidationSnapshot,
    bounds: BonusBounds,
    curve: &LiquidationCurve,
) -> (Wad, Bps) {
    let scaled_bonus = calculate_linear_bonus_with_target(
        env,
        snap.hf,
        bounds.base,
        bounds.max,
        curve,
        curve.target_hf,
    );

    let bonus = match max_hf_preserving_bonus_bps(snap) {
        None => scaled_bonus,
        Some(_) if snap.total_collateral < snap.total_debt => {
            let one_plus_base = Wad::ONE.checked_add(env, bounds.base.to_wad(env));
            let backed = snap.total_collateral.div_floor(env, one_plus_base);
            return (backed.min(snap.total_debt), bounds.base);
        }
        Some(cap) if cap < bounds.base.raw() => {
            return (snap.total_debt, Bps::from(cap.max(0)));
        }
        Some(cap) => Bps::from(scaled_bonus.raw().min(cap)),
    };

    let ideal = liquidation_at_target(env, snap, bonus, curve.target_hf);

    let remaining_debt = snap.total_debt.checked_sub(env, ideal);
    if remaining_debt > Wad::ZERO && remaining_debt < Wad::from(BAD_DEBT_USD_THRESHOLD) {
        return (snap.total_debt, bonus);
    }

    (ideal, bonus)
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L81-109)
```rust
/// Executes a scheduled operation against `target` once its delay has elapsed and
/// it has not expired, and returns the invocation's result. Rejects operations
/// that target this contract itself (use `execute_self` for those). Clears the
/// operation's scheduled state on completion.
pub(crate) fn execute(
    env: &Env,
    executor: Option<Address>,
    target: Address,
    function: Symbol,
    args: Vec<Val>,
    predecessor: BytesN<32>,
    salt: BytesN<32>,
) -> Val {
    assert_with_error!(
        env,
        target != env.current_contract_address(),
        GenericError::InternalError
    );
    let operation = Operation {
        target,
        function,
        args,
        predecessor,
        salt,
    };
    let operation_id = prepare_execute(env, executor.as_ref(), &operation);
    let result = execute_operation(env, &operation);
    finish_execute(env, &operation_id);
    result
```
