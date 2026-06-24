Audit Report

## Title
Blind ICRC-2 Allowance Overwrite in `approve_treasury_manager` Enables Treasury Over-Drain via Concurrent Deposit Proposals - (File: rs/sns/governance/src/extensions.rs)

## Summary
`approve_treasury_manager` calls `icrc2_approve` with `expected_allowance: None` for both SNS and ICP ledgers, causing the ledger to blindly overwrite any existing allowance. Because SNS governance spawns proposal execution futures concurrently via `spawn_in_canister_env`, two concurrent `ExecuteExtensionOperation` deposit proposals can interleave such that the treasury manager accumulates and spends both allowances, draining more treasury funds than any single governance vote authorized. The code comment at the root cause site explicitly claims this pattern eliminates double-spend risk, which is incorrect.

## Finding Description

**Root cause — `approve_treasury_manager` passes `None` as `expected_allowance`:**

`rs/sns/governance/src/extensions.rs` lines 791–802 call `icrc2_approve` with `None` for both the SNS ledger and the ICP ledger. The comment at line 791–792 states: *"If expected_allowance is None, the ledger blindly overwrites any existing allowance (even if non-zero). Therefore, there is no risk of double spending."* This reasoning is wrong.

**ICRC-2 ledger behavior — `None` skips the compare-and-set guard:**

`rs/ledger_suite/common/ledger_core/src/approvals.rs` lines 278–292 confirm: when `expected_allowance` is `None`, the `if let Some(expected_allowance)` branch is not entered, so no check against the current allowance is performed and the value is unconditionally overwritten.

**Concurrent execution — proposals run in parallel:**

`rs/sns/governance/src/governance.rs` line 2133 calls `spawn_in_canister_env(governance.perform_action(proposal_id, action))`. This spawns each proposal's execution as an independent async task. Every `await` inside `execute_treasury_manager_deposit` is a yield point where another spawned task can run.

**No concurrency guard exists:**

A grep for `in_progress`, `lock`, `mutex`, and `executing` in `rs/sns/governance/src/extensions.rs` returns no matches. There is no per-extension or per-operation execution lock preventing two deposit proposals from running simultaneously.

**Exploit interleaving (two concurrent deposit proposals, Proposal A = 100 SNS, Proposal B = 200 SNS):**

1. Both proposals are adopted and `perform_action` is spawned for each.
2. Proposal A reaches `approve_treasury_manager(100 SNS)` → ledger sets allowance to 100.
3. Proposal B reaches `approve_treasury_manager(200 SNS)` → ledger **blindly overwrites** allowance to 200.
4. Proposal A resumes and calls `treasury_manager.deposit(100 SNS)` → treasury manager calls `icrc2_transfer_from(100)` → succeeds, allowance drops to 100.
5. Proposal B resumes and calls `treasury_manager.deposit(200 SNS)` → treasury manager calls `icrc2_transfer_from(200)` → succeeds, allowance drops to 0.
6. **Total drained: 300 SNS. Maximum authorized by any single proposal: 200 SNS.**

The same race applies to ICP via `self.nns_ledger.icrc2_approve(...)` at lines 812–820.

The two call sites are `ValidatedRegisterExtension::execute` (lines 545–551) and `execute_treasury_manager_deposit` (lines 1566–1573), meaning the race can also be triggered by a `RegisterExtension` proposal interleaving with a deposit proposal.

## Impact Explanation

This is an SNS treasury authorization bypass: governance votes authorize a specific amount per proposal, but the execution mechanism allows the treasury manager to receive and spend a combined allowance exceeding what any single vote authorized. The result is unauthorized transfer of SNS tokens and ICP from the SNS treasury to the treasury manager canister, constituting unauthorized access to canister-controlled governance funds. This matches the **High** impact class: *"Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds where exploitation requires meaningful per-target work or other constraints"* and *"Significant SNS security impact with concrete user or protocol harm."*

## Likelihood Explanation

Any SNS DAO that has registered a treasury manager extension and can pass two deposit proposals within the same voting window is exposed. The attacker needs sufficient voting power to pass two proposals — no privileged system access is required beyond normal neuron participation. The treasury manager is a new feature, making this a near-term risk as SNS DAOs begin adopting it. The interleaving is deterministic given the `spawn_in_canister_env` execution model and is not dependent on timing luck at the network level.

## Recommendation

Pass the current allowance as `expected_allowance` to implement a compare-and-set pattern. Before calling `icrc2_approve`, read the current allowance via `icrc2_allowance` and supply it:

```rust
let current = self.ledger.icrc2_allowance(from_account, to).await?;
self.ledger.icrc2_approve(
    to,
    sns_amount_e8s,
    Some(expiry_time_nsec),
    self.transaction_fee_e8s_or_panic(),
    self.sns_treasury_subaccount(),
    Some(current.allowance), // expected_allowance = current value
).await?;
```

Alternatively, introduce a per-extension execution lock (similar to the `UpgradeSnsToNextVersion` in-progress flag) that prevents two `ExecuteExtensionOperation` proposals for the same extension canister from executing concurrently.

## Proof of Concept

A deterministic PocketIC integration test can reproduce this:

1. Deploy an SNS with a registered treasury manager extension canister.
2. Submit and adopt two `ExecuteExtensionOperation` deposit proposals (e.g., 100 SNS and 200 SNS) in the same voting round so both reach `Adopted` status simultaneously.
3. Advance the PocketIC state machine to trigger `start_proposal_execution` for both proposals.
4. Interleave execution: allow Proposal A to complete `approve_treasury_manager` (SNS allowance = 100), then allow Proposal B to complete `approve_treasury_manager` (SNS allowance = 200), then allow Proposal A to call `deposit` (allowance → 100), then allow Proposal B to call `deposit` (allowance → 0).
5. Assert that the treasury manager received 300 SNS total while the maximum authorized by any single proposal was 200 SNS.

The root cause is directly observable by inspecting the ICRC-2 allowance table after step 4 and comparing the total `icrc2_transfer_from` amounts against the per-proposal authorized amounts.