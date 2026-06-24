Audit Report

## Title
SNS Governance Canister Panic via Race Between `check_upgrade_status` and `fail_stuck_upgrade_in_progress` - (File: `rs/sns/governance/src/governance.rs`)

## Summary
A race condition exists between the async periodic task `check_upgrade_status` and the publicly callable synchronous method `fail_stuck_upgrade_in_progress`. When `fail_stuck_upgrade_in_progress` executes during the async suspension window of `check_upgrade_status`, it clears `pending_version` to `None`. Upon resumption, `check_upgrade_status` unconditionally calls `.unwrap()` on `pending_version` at line 6180, causing the canister to trap. The committed state from `fail_stuck_upgrade_in_progress` (proposal marked `Failed`, `pending_version = None`) is not rolled back, permanently desynchronizing SNS governance version state from the actual deployed canister state.

## Finding Description

**Primary panic point — `.unwrap()` on cleared `pending_version` at line 6180:**

`check_upgrade_status` suspends at the `await` on line 6174:
```rust
let running_version: Result<Version, String> =
    get_running_version(&*self.env, self.proto.root_canister_id_or_panic()).await;
```
Upon resumption, it unconditionally unwraps `pending_version` at lines 6177–6181:
```rust
self.proto
    .pending_version
    .as_mut()
    .unwrap()          // ← panics if pending_version is None
    .checking_upgrade_lock = 0;
```
The comment at line 6183 explicitly states "We cannot panic or we will get stuck with `checking_upgrade_lock` set to true" — yet the `.unwrap()` immediately above creates exactly that panic path.

**`fail_stuck_upgrade_in_progress` clears `pending_version` during the await window:**

`fail_stuck_upgrade_in_progress` (lines 6328–6361) is a public update call with no caller authorization. It explicitly ignores `checking_upgrade_lock` (lines 6337–6338: "Maybe, we should look at the `checking_upgrade_lock` field..."). When the deadline has elapsed, it calls `complete_sns_upgrade_to_next_version`, which at lines 6305–6309 calls `set_proposal_execution_status` (transitioning the proposal from `Adopted` → `Failed`) and then sets `self.proto.pending_version = None`.

**Secondary panic — hard `assert_eq!` at line 1720:**

`set_proposal_execution_status` contains:
```rust
assert_eq!(proposal.status(), ProposalDecisionStatus::Adopted);
```
This is a hard assert (not `debug_assert_eq!`) with no early-return guard for already-terminal proposals. If both paths somehow reach it for the same proposal, the second call also traps.

**Race sequence:**
1. `check_upgrade_status` increments `checking_upgrade_lock` to 1 (lines 6146–6150), clones `pending_version` locally, then suspends at the `await` on line 6174.
2. During the await, an unprivileged caller invokes `fail_stuck_upgrade_in_progress`. The deadline has elapsed. It calls `complete_sns_upgrade_to_next_version` → `set_proposal_execution_status` (proposal X: `Adopted` → `Failed`) → `pending_version = None`. This message commits.
3. `check_upgrade_status` resumes. `self.proto.pending_version` is now `None`. The `.unwrap()` at line 6180 panics. This message's state changes are rolled back.
4. Net committed state: proposal X = `Failed`, `pending_version = None`, `checking_upgrade_lock` effectively lost.

## Impact Explanation

This matches the **High** bounty impact: "Significant SNS security impact with concrete user or protocol harm." Specifically:

- The SNS governance canister heartbeat traps on every subsequent invocation of `check_upgrade_status` until the panic is resolved (though `pending_version = None` means `should_check_upgrade_status` returns false, so the heartbeat loop itself is not permanently broken — but the upgrade tracking is).
- If the underlying canister upgrade actually succeeded, governance permanently records it as `Failed`. `deployed_version` is not updated. Subsequent upgrade proposals operate against a stale baseline version, potentially blocking or corrupting all future SNS upgrade proposals.
- An unprivileged user can trigger this with no special privileges, keys, or governance majority.

## Likelihood Explanation

- `fail_stuck_upgrade_in_progress` has no caller authorization check — any principal can call it.
- The 5-minute `mark_failed_at_seconds` deadline is reachable whenever an upgrade is slow (large WASM, loaded subnet).
- `check_upgrade_status` is invoked on every heartbeat and makes at least one async inter-canister call (`get_running_version`), creating a recurring multi-second window per heartbeat cycle.
- An attacker can spam `fail_stuck_upgrade_in_progress` at high frequency after the deadline to reliably land within the async window.
- No victim mistakes, social engineering, or privileged access required.

## Recommendation

1. **Re-check `pending_version` after async resumption in `check_upgrade_status`:** After the `await` at line 6174, check whether `pending_version` is still `Some` before calling `.unwrap()`. If it is `None`, log a warning and return — the upgrade was already resolved by another path.
2. **Respect `checking_upgrade_lock` in `fail_stuck_upgrade_in_progress`:** Implement the acknowledged TODO at lines 6337–6338: refuse to proceed (or require a `force` flag) if `checking_upgrade_lock > 0`.
3. **Replace the hard `assert_eq!` in `set_proposal_execution_status` (SNS):** Mirror the NNS behavior — use `debug_assert_eq!` and add an early-return guard if the proposal is already in a terminal state (`executed_timestamp_seconds != 0` or `failed_timestamp_seconds != 0`).

## Proof of Concept

```
1. Submit an SNS UpgradeSnsToNextVersion proposal and get it adopted.
2. Wait for mark_failed_at_seconds (5 minutes after adoption) to elapse.
3. In a tight loop, send update calls to sns_governance.fail_stuck_upgrade_in_progress({}).
4. One call lands while check_upgrade_status is suspended at its async get_running_version call.
5. fail_stuck_upgrade_in_progress commits: proposal → Failed, pending_version → None.
6. check_upgrade_status resumes, hits .unwrap() on None pending_version at line 6180 → canister traps.
7. Observable result: proposal permanently marked Failed regardless of actual upgrade outcome;
   SNS governance deployed_version not updated; all future upgrade proposals operate on stale version baseline.

Reproducible via a PocketIC integration test:
- Set up SNS with a pending upgrade proposal past its mark_failed_at_seconds.
- Interleave a fail_stuck_upgrade_in_progress call between the outgoing and incoming
  inter-canister call messages of check_upgrade_status using PocketIC's tick control.
- Assert that the subsequent heartbeat tick does not panic and that deployed_version
  reflects the actual running version — this assertion will fail, confirming the bug.
```