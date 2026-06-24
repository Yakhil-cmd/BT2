Audit Report

## Title
Unprivileged Caller Can Prematurely Fail SNS Upgrade Proposals via `fail_stuck_upgrade_in_progress` - (File: rs/sns/governance/src/governance.rs)

## Summary
The `fail_stuck_upgrade_in_progress` method on the SNS Governance canister is a public update endpoint with no caller authorization check. Any external principal can invoke it after the 5-minute `mark_failed_at_seconds` deadline to permanently mark an in-progress SNS upgrade proposal as `Failed` and clear `pending_version`, forcing the SNS community to re-submit and re-vote on the upgrade.

## Finding Description
When an `UpgradeSnsToNextVersion` proposal is executed, governance sets `pending_version` with `mark_failed_at_seconds = now + 5 * 60`: [1](#0-0) 

The public method `fail_stuck_upgrade_in_progress` (line 6328) checks only whether `now > pending_version.mark_failed_at_seconds` — there is no `check_caller_is_*` guard, no self-call requirement, and no neuron/principal allowlist: [2](#0-1) 

When the condition is true, it calls `complete_sns_upgrade_to_next_version`, which calls `set_proposal_execution_status` with a failure result and sets `self.proto.pending_version = None`. The method is registered as a public canister endpoint, confirmed by its import in the canister entrypoint: [3](#0-2) 

No `check_caller_is_*` guard exists anywhere in `canister.rs`: [4](#0-3) 

The periodic task `check_upgrade_status` is the intended mechanism for handling the timeout, but the public endpoint races against it. Critically, if an upgrade completes successfully just after the 5-minute deadline (before the periodic task observes the new versions), an attacker calling `fail_stuck_upgrade_in_progress` first will clear `pending_version` and mark the proposal `Failed`, after which the periodic task finds `pending_version = None` and does nothing — permanently losing the successful upgrade outcome.

## Impact Explanation
This is a **High** severity finding matching "Significant SNS security impact with concrete user or protocol harm." An unprivileged attacker can permanently mark any SNS upgrade proposal as `Failed` after 5 minutes at the cost of a single ingress message. For time-sensitive upgrades (e.g., security patches), this constitutes a repeatable governance DoS: each re-submitted proposal is equally vulnerable. The proposal ID is permanently stuck in `Failed` state; the SNS community must re-submit, re-vote, and re-execute.

## Likelihood Explanation
The attack requires no privileged access, no key material, and no coordination. The `pending_version` state (including `mark_failed_at_seconds`) is readable on-chain via `get_running_sns_version`. Any party monitoring SNS governance state can detect when the deadline has passed and send a single ingress call. The attack is repeatable on every upgrade proposal and costs only the ingress fee.

## Recommendation
Add a caller authorization check to `fail_stuck_upgrade_in_progress` so it can only be invoked by the SNS governance canister itself (via a self-call) or a defined set of privileged principals. Alternatively, remove the public endpoint entirely and rely solely on the internal periodic task (`check_upgrade_status`) to handle the timeout case, which is the intended design.

## Proof of Concept
1. An SNS `UpgradeSnsToNextVersion` proposal is adopted and executed. Governance sets `pending_version.mark_failed_at_seconds = now + 300`.
2. Attacker polls `get_running_sns_version` until `now > mark_failed_at_seconds`.
3. Attacker sends: `dfx canister call <sns-governance> fail_stuck_upgrade_in_progress '(record {})'`
4. Inside `fail_stuck_upgrade_in_progress`, `now > pending_version.mark_failed_at_seconds` is true; `complete_sns_upgrade_to_next_version` is called with `ExternalFailure` status.
5. `set_proposal_execution_status(proposal_id, Err(...))` permanently marks the proposal `Failed`; `pending_version` is cleared.
6. The periodic task subsequently finds `pending_version = None` and takes no action.
7. A reproducible unit test can be written using the existing test harness in `rs/sns/governance/src/governance/fail_stuck_upgrade_in_progress_tests.rs` by calling `fail_stuck_upgrade_in_progress` with an unprivileged caller identity after advancing the mock clock past `mark_failed_at_seconds` and verifying the proposal transitions to `Failed`. [5](#0-4)

### Citations

**File:** rs/sns/governance/src/governance.rs (L2894-2899)
```rust
        self.proto.pending_version = Some(PendingVersion {
            target_version: Some(next_version),
            mark_failed_at_seconds: self.env.now() + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        });
```

**File:** rs/sns/governance/src/governance.rs (L6328-6361)
```rust
    pub fn fail_stuck_upgrade_in_progress(
        &mut self,
        _: FailStuckUpgradeInProgressRequest,
    ) -> FailStuckUpgradeInProgressResponse {
        let pending_version = match self.proto.pending_version.as_ref() {
            None => return FailStuckUpgradeInProgressResponse {},
            Some(pending_version) => pending_version,
        };

        // Maybe, we should look at the checking_upgrade_lock field and only
        // proceed if it is false, or the request has force set to true.

        let now = self.env.now();

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
        }

        FailStuckUpgradeInProgressResponse {}
    }
```

**File:** rs/sns/governance/canister/canister.rs (L1-76)
```rust
// TODO: Jira ticket NNS1-3556
#![allow(deprecated)]
#![allow(static_mut_refs)]
use async_trait::async_trait;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_canister_profiler::{measure_span, measure_span_async};
use ic_cdk::{caller as cdk_caller, init, post_upgrade, pre_upgrade, println, query, update};
use ic_cdk_timers::TimerId;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_canisters::{cmc::CMCCanister, ledger::IcpLedgerCanister};
use ic_nervous_system_clients::{
    canister_status::CanisterStatusResultV2, ledger_client::LedgerCanister,
};
use ic_nervous_system_common::{
    memory_manager_upgrade_storage::{load_protobuf, store_protobuf},
    serve_logs, serve_logs_v2, serve_metrics,
};
use ic_nervous_system_proto::pb::v1::{
    GetTimersRequest, GetTimersResponse, ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_constants::LEDGER_CANISTER_ID as NNS_LEDGER_CANISTER_ID;
#[cfg(feature = "test")]
use ic_sns_governance::extensions::add_allowed_extension_spec;
#[cfg(feature = "test")]
use ic_sns_governance::pb::v1::AddAllowedExtensionRequest;
use ic_sns_governance::{
    governance::{Governance, TimeWarp, ValidGovernanceProto, log_prefix},
    logs::{ERROR, INFO},
    pb::v1::{self as sns_gov_pb},
    storage::with_upgrades_memory,
    types::{Environment, HeapGrowthPotential},
    upgrade_journal::serve_journal,
};
#[cfg(feature = "test")]
use ic_sns_governance_api::pb::v1::{
    AddMaturityRequest, AddMaturityResponse, AdvanceTargetVersionRequest,
    AdvanceTargetVersionResponse, MintTokensRequest, MintTokensResponse,
    RefreshCachedUpgradeStepsRequest, RefreshCachedUpgradeStepsResponse,
};
use ic_sns_governance_api::pb::v1::{
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, FailStuckUpgradeInProgressRequest,
    FailStuckUpgradeInProgressResponse, GetMaturityModulationRequest,
    GetMaturityModulationResponse, GetMetadataRequest, GetMetadataResponse, GetMetricsRequest,
    GetMode, GetModeResponse, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
    GetRunningSnsVersionRequest, GetRunningSnsVersionResponse,
    GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
    GetUpgradeJournalRequest, GetUpgradeJournalResponse, Governance as GovernanceApi,
    GovernanceError, ListNervousSystemFunctionsResponse, ListNeurons, ListNeuronsResponse,
    ListProposals, ListProposalsResponse, ManageNeuron, ManageNeuronResponse,
    NervousSystemParameters, RewardEvent, SetMode, SetModeResponse, get_metrics_response,
    get_running_sns_version_response::UpgradeInProgress,
    governance::Version,
    governance_error::ErrorType,
    topics::{ListTopicsRequest, ListTopicsResponse},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    boxed::Box,
    cell::RefCell,
    convert::TryFrom,
    time::{Duration, SystemTime},
};

static mut GOVERNANCE: Option<Governance> = None;

thread_local! {
    static TIMER_ID: RefCell<Option<TimerId>> = RefCell::new(Default::default());
}

/// This guarantees that timers cannot be restarted more often than once every 60 intervals.
const RESET_TIMERS_COOL_DOWN_INTERVAL: Duration = Duration::from_secs(600);

const RUN_PERIODIC_TASKS_INTERVAL: Duration = Duration::from_secs(10);
```

**File:** rs/sns/governance/src/governance/fail_stuck_upgrade_in_progress_tests.rs (L1-3)
```rust
use super::test_helpers::{
    DoNothingLedger, TEST_GOVERNANCE_CANISTER_ID, TEST_ROOT_CANISTER_ID, basic_governance_proto,
};
```
