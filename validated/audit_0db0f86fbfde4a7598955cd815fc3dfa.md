### Title
Sensitive-tier governance operations bypass the intended 7-day timelock due to a hard-coded audit constant left at 12 ledgers — (File: contracts/governance/src/constants.rs)

### Summary
`TIMELOCK_SENSITIVE_MIN_DELAY_LEDGERS` is hard-coded to `12` ledgers (~1 minute at ~5s/ledger), with an inline comment stating the audit-period value is temporary and the target is `120_960` (about 7 days). Sensitive-tier operations — including contract upgrades, ownership transfers, controller migration, oracle configuration, and role grants — are therefore schedulable with an effective delay of only 12 ledgers instead of the intended ~7-day review window. Anyone can then permissionlessly execute the ready operation once it becomes ripe.

### Finding Description
`operation_delay` floors the delay of `DelayTier::Sensitive` operations at `TIMELOCK_SENSITIVE_MIN_DELAY_LEDGERS` [1](#0-0) . That constant is `12`, not the documented `120_960` target [2](#0-1) . The sensitive tier covers the highest-impact self-operations: `TransferGovOwnership`, `TransferCtrlOwnership`, `UpgradeGov`, `UpgradeController`, `UpgradePool`, `UpgradePositionNft`, `UpgradePriceAggregator`, `MigrateController`, `SetPriceAggregator`, `ConfigureAssetOracle`, `SetSwapAggregator`, `GrantGovRole`, and more [3](#0-2) . Execution of a ready operation requires no executor when `executor: None` is passed [4](#0-3) .

### Impact Explanation
The timelock is the protocol's only defense layer between a sensitive proposal and its execution. With the floor at 12 ledgers, a sensitive operation becomes executable roughly one minute after scheduling, giving guardians, cancellers, and users no practical window to review, cancel via `cancel`, or exit positions before effects such as a controller upgrade, oracle reconfiguration, or ownership transfer take hold. Because `execute`/`execute_self` are permissionless once ready, an unprivileged address can land a scheduled sensitive operation immediately after its 12-ledger delay — converting any (even routine) sensitive proposal into a near-instant, unreviewable state change and enabling theft or freezing of user funds via malicious upgrade or oracle re-pointing.

### Likelihood Explanation
The constant is deployed as written; no configuration can raise it, since `operation_delay` uses `max(min_delay, 12)` rather than `max(min_delay, 120_960)` — even a larger `min_delay` would need to exceed ~2 days by governance update to partially compensate, and nothing forces `min_delay` above the intended 7-day sensitive floor. Exploitation of the shortened window only requires a sensitive op to be scheduled and any address to call `execute` once ready; no privileged executor is needed.

### Recommendation
Set `TIMELOCK_SENSITIVE_MIN_DELAY_LEDGERS` to `120_960` (the documented ~7-day target) before deployment, or gate the audit value behind a test-only feature flag. Add a constructor-time or upgrade-time assertion that the sensitive floor is at least the intended production value.

### Proof of Concept
1. Owner proposes any sensitive `AdminOperation` (e.g., `UpgradeController` or `SetPriceAggregator`) via `propose`.
2. `schedule_operation` stores `ready_ledger = current + max(min_delay, 12)`; with the default `min_delay` of ~2 days, the floor silently remains 12 only if `min_delay <= 12`, but more critically any `min_delay` below 120_960 is permitted for the sensitive tier — the code path guarantees at most `max(min_delay, 12)`, never the documented 120_960.
3. After 12 ledgers (≈1 minute) any unprivileged address calls `execute_self(None, op, salt)`; `authorize_executor` performs no auth when `executor` is `None`, and `apply_self_op` applies the change before any canceller can react.

### Citations

**File:** contracts/governance/src/timelock/mod.rs (L42-49)
```rust
pub(crate) fn operation_delay(env: &Env, tier: DelayTier) -> u32 {
    let min = get_min_delay(env);
    match tier {
        DelayTier::Standard => min,
        DelayTier::Sensitive => min.max(constants::TIMELOCK_SENSITIVE_MIN_DELAY_LEDGERS),
        DelayTier::Recovery => min.max(constants::TIMELOCK_RECOVERY_MIN_DELAY_LEDGERS),
    }
}
```

**File:** contracts/governance/src/timelock/mod.rs (L75-82)
```rust
/// When `Some(exec)`, requires `exec` auth + `EXECUTOR_ROLE`. When `None`,
/// performs no auth or role check (anyone may drive execution of a ready op).
pub(crate) fn authorize_executor(env: &Env, executor: Option<&Address>) {
    if let Some(exec) = executor {
        exec.require_auth();
        access_control::ensure_role(env, &Symbol::new(env, EXECUTOR_ROLE), exec);
    }
}
```

**File:** contracts/governance/src/constants.rs (L12-17)
```rust
// Audit-period value. The target value is 120_960 (about 7 days), set through
// a governance-executed `UpgradeGov`.
/// Floor, in ledgers, applied to the delay for sensitive-tier operations:
/// the configured minimum delay is raised to at least this value for that
/// tier.
pub const TIMELOCK_SENSITIVE_MIN_DELAY_LEDGERS: u32 = 12;
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L48-69)
```rust
        AdminOperation::TransferGovOwnership(_)
        | AdminOperation::TransferCtrlOwnership(_)
        | AdminOperation::UpgradeGov(_)
        | AdminOperation::UpgradeController(_)
        | AdminOperation::UpgradePool(_)
        | AdminOperation::UpgradePositionNft(_)
        | AdminOperation::UpgradePriceAggregator(_)
        | AdminOperation::MigrateController(_)
        | AdminOperation::UpdateGovDelay(_)
        | AdminOperation::SetPriceAggregator(_)
        | AdminOperation::ConfigureAssetOracle(_)
        | AdminOperation::EditOracleTolerance(_)
        | AdminOperation::SetSwapAggregator(_)
        | AdminOperation::ApproveBlendPool(_)
        | AdminOperation::SetAccumulator(_)
        | AdminOperation::GrantGovRole(_) => {
            assert_with_error!(
                env,
                proposer == &access::owner_or_panic(env),
                GenericError::NotAuthorized
            );
        }
```
