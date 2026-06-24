Audit Report

## Title
Unauthenticated `fail_stuck_upgrade_in_progress` Endpoint Allows Any Caller to Corrupt SNS Upgrade State After Deadline - (File: rs/sns/governance/canister/canister.rs)

## Summary
The SNS governance canister exposes `fail_stuck_upgrade_in_progress` as a public `#[update]` endpoint with no caller authentication. Any unprivileged ingress sender can invoke it after the 5-minute `mark_failed_at_seconds` deadline to forcibly mark an in-progress (or already-completed) upgrade proposal as failed, leaving `deployed_version` permanently stale and corrupting the SNS upgrade state machine for all future upgrade proposals.

## Finding Description
`perform_upgrade_to_next_sns_version_legacy` sets `pending_version` with a 5-minute deadline after kicking off the actual canister upgrade: [1](#0-0) 

The periodic task `check_upgrade_status` (running every 10 seconds) is the intended path to confirm completion and call `complete_sns_upgrade_to_next_version` with `Status::Success` and the new `deployed_version`: [2](#0-1) 

The public endpoint `fail_stuck_upgrade_in_progress` in `canister.rs` performs no caller check whatsoever — it directly delegates to the governance implementation: [3](#0-2) 

The governance implementation only checks whether the current time exceeds `mark_failed_at_seconds`: [4](#0-3) 

When triggered, `complete_sns_upgrade_to_next_version` is called with `deployed_version = None`, so `deployed_version` is never updated to the new version and the proposal is permanently marked failed: [5](#0-4) 

The `checking_upgrade_lock` mechanism can cause `check_upgrade_status` to return early without confirming success if concurrent timer calls are in flight, extending the exploitable window: [6](#0-5) 

## Impact Explanation
This is a **High** severity SNS governance impact. An attacker who calls `fail_stuck_upgrade_in_progress` after the 5-minute deadline (but before `check_upgrade_status` confirms success) causes: (1) the upgrade proposal is permanently marked failed even though the actual canister wasm was already installed; (2) `deployed_version` remains at the pre-upgrade value, diverging from the actual running version; (3) all future `UpgradeSnsToNextVersion` proposals compute the "next version" from the stale `deployed_version`, potentially re-applying the same upgrade step or skipping versions on the blessed upgrade path; (4) `check_no_upgrades_in_progress` is unblocked, allowing a new upgrade proposal to execute immediately against the wrong baseline. This matches the allowed impact: "Significant SNS security impact with concrete user or protocol harm." [7](#0-6) 

## Likelihood Explanation
The attack is reachable by any unprivileged ingress sender with no special privileges. The attack window opens exactly at `mark_failed_at_seconds` (5 minutes after upgrade initiation) and closes when `check_upgrade_status` next confirms success (periodic task runs every 10 seconds). An attacker monitoring on-chain state can observe `pending_version` being set and call `fail_stuck_upgrade_in_progress` precisely after the deadline. The `checking_upgrade_lock > 1` condition can extend the window if concurrent timer calls are in flight. The window is narrow but deterministically reachable by any external observer. [8](#0-7) 

## Recommendation
Add caller authentication to `fail_stuck_upgrade_in_progress` in `canister.rs`. Only privileged principals — such as the SNS root canister, or neurons via a governance proposal — should be permitted to invoke this abort path. Alternatively, before marking the proposal failed, query the root canister for the actual running version and update `deployed_version` accordingly, so that even an externally-triggered abort cannot leave the version state inconsistent. [3](#0-2) 

## Proof of Concept
1. An `UpgradeSnsToNextVersion` proposal passes; `perform_upgrade_to_next_sns_version_legacy` sets `pending_version` with `mark_failed_at_seconds = now + 300`.
2. The actual canister upgrade completes on-chain within seconds, but `check_upgrade_status` has not yet confirmed it (e.g., `checking_upgrade_lock > 1` from a concurrent timer call, or the periodic task simply has not fired yet).
3. After 300 seconds, an unprivileged attacker sends an ingress call to `fail_stuck_upgrade_in_progress({})`.
4. The function finds `now > mark_failed_at_seconds`, calls `complete_sns_upgrade_to_next_version` with `deployed_version = None` and `Status::ExternalFailure`.
5. The proposal is marked failed; `deployed_version` stays at the old version; `pending_version` is cleared.
6. A unit test confirming this exact behavior already exists in `fail_stuck_upgrade_in_progress_tests.rs` — `test_fails_proposal_and_removes_upgrade_if_upgrade_attempt_is_expired` demonstrates that calling the function after the deadline marks the proposal failed and leaves `deployed_version` unchanged, with no caller restriction enforced. [9](#0-8)

### Citations

**File:** rs/sns/governance/src/governance.rs (L2775-2788)
```rust
        if self.proto.pending_version.is_some() {
            return Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                format!(
                    "Upgrade lock acquired (expires at {:?}), not upgrading",
                    self.proto
                        .pending_version
                        .as_ref()
                        .map(|p| p.mark_failed_at_seconds)
                ),
            ));
        }

        Ok(())
```

**File:** rs/sns/governance/src/governance.rs (L2894-2899)
```rust
        self.proto.pending_version = Some(PendingVersion {
            target_version: Some(next_version),
            mark_failed_at_seconds: self.env.now() + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        });
```

**File:** rs/sns/governance/src/governance.rs (L6145-6157)
```rust
        // Mark the check as active before async call.
        self.proto
            .pending_version
            .as_mut()
            .unwrap()
            .checking_upgrade_lock += 1;

        let lock = self
            .proto
            .pending_version
            .as_ref()
            .unwrap()
            .checking_upgrade_lock;
```

**File:** rs/sns/governance/src/governance.rs (L6169-6171)
```rust
        if lock > 1 {
            return;
        }
```

**File:** rs/sns/governance/src/governance.rs (L6261-6266)
```rust
        self.complete_sns_upgrade_to_next_version(
            proposal_id,
            status,
            message,
            Some(target_version),
        );
```

**File:** rs/sns/governance/src/governance.rs (L6305-6313)
```rust
        if let Some(proposal_id) = proposal_id {
            self.set_proposal_execution_status(proposal_id, result);
        }

        self.proto.pending_version = None;

        if let Some(deployed_version) = deployed_version {
            self.proto.deployed_version.replace(deployed_version);
        }
```

**File:** rs/sns/governance/src/governance.rs (L6342-6357)
```rust
        if now > pending_version.mark_failed_at_seconds {
            let message = format!(
                "Upgrade marked as failed at {}. \
                Governance upgrade was manually aborted by calling fail_stuck_upgrade_in_progress \
                after mark_failed_at_seconds ({}). Setting upgrade to failed to unblock retry.",
                format_timestamp_for_humans(now),
                pending_version.mark_failed_at_seconds,
            );
            let status = upgrade_journal_entry::upgrade_outcome::Status::ExternalFailure(Empty {});

            self.complete_sns_upgrade_to_next_version(
                pending_version.proposal_id,
                status,
                message,
                None,
            );
```

**File:** rs/sns/governance/canister/canister.rs (L526-535)
```rust
/// Marks an in progress upgrade that has passed its deadline as failed.
#[update]
fn fail_stuck_upgrade_in_progress(
    request: FailStuckUpgradeInProgressRequest,
) -> FailStuckUpgradeInProgressResponse {
    log!(INFO, "fail_stuck_upgrade_in_progress");
    FailStuckUpgradeInProgressResponse::from(governance_mut().fail_stuck_upgrade_in_progress(
        sns_gov_pb::FailStuckUpgradeInProgressRequest::from(request),
    ))
}
```

**File:** rs/sns/governance/src/governance/fail_stuck_upgrade_in_progress_tests.rs (L216-298)
```rust
#[test]
fn test_fails_proposal_and_removes_upgrade_if_upgrade_attempt_is_expired() {
    // Step 1: Prepare the world

    let env = {
        let mut env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));

        // Note that NativeEnvironment only advances time when you tell it
        // to. Therefore, this is the time that Governance will see
        // throughout this test.
        env.now = UPGRADE_DEADLINE_TIMESTAMP_SECONDS + 1;

        env
    };

    let mut governance = Governance::new(
        ValidGovernanceProto::try_from(GOVERNANCE_PROTO.clone()).unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // The code being tested is supposed to affect these fields. We
    // inspect them here to make sure that any expected changes are
    // real, not just because the world was (accidentally) already the
    // way we expected them afterwards.
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(SNS_VERSION_2.clone()),
            mark_failed_at_seconds: UPGRADE_DEADLINE_TIMESTAMP_SECONDS,
            checking_upgrade_lock: 10,
            proposal_id: Some(UPGRADE_PROPOSAL_ID),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );

    // Step 2: Run the code being tested.
    assert_eq!(
        governance.fail_stuck_upgrade_in_progress(FailStuckUpgradeInProgressRequest {}),
        FailStuckUpgradeInProgressResponse {},
    );

    // Step 3: Inspect results.

    // Assert pending version has been cleared.
    let pending_version = &governance.proto.pending_version;
    assert!(pending_version.is_none(), "{pending_version:#?}");
    // Assert deployed_version unchanged from before.
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        SNS_VERSION_1.clone()
    );

    // Assert proposal failed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId {
            id: UPGRADE_PROPOSAL_ID,
        }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_ne!(proposal_data.failed_timestamp_seconds, 0);

    // Inspect the proposal's failure_reason.
    let governance_error = proposal_data.failure_reason.unwrap();
    assert_eq!(
        ErrorType::try_from(governance_error.error_type),
        Ok(ErrorType::External),
        "{governance_error:#?}",
    );
    assert!(
        governance_error.error_message.contains("manually aborted"),
        "{governance_error:#?}",
    );
```
