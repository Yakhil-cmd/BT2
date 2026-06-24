Audit Report

## Title
Unbounded Ballot Reset via Resubmission Allows Indefinite Prevention of Root Proposal Rejection - (File: rs/nns/handlers/root/impl/src/root_proposals.rs)

## Summary
`submit_root_proposal_to_upgrade_governance_canister` unconditionally replaces any existing proposal from the same NNS node operator principal, resetting all accumulated ballots to their initial state with no cooldown, rate limit, or minimum elapsed time. A single malicious NNS node operator can exploit this to monitor the "no" vote tally and resubmit just before the Byzantine rejection threshold (`f+1` "no" votes) is reached, permanently preventing formal rejection of their proposal and forcing all other node operators to re-cast their votes after every reset.

## Finding Description
Root proposals are stored in a `thread_local` `BTreeMap<PrincipalId, GovernanceUpgradeRootProposal>` keyed by the proposer's principal. [1](#0-0) 

When `submit_root_proposal_to_upgrade_governance_canister` is called by a node operator who already has a pending proposal, the function logs a warning and unconditionally replaces the old entry — including all ballots cast by other node operators — with a fresh proposal carrying only the proposer's own automatic "yes" votes: [2](#0-1) 

The sole access control is a check that the caller operates at least one node on the NNS subnet: [3](#0-2) 

The `MAX_TIME_FOR_GOVERNANCE_UPGRADE_ROOT_PROPOSAL` (7 days) expiry is enforced only inside `vote_on_root_proposal_to_upgrade_governance_canister`, not during submission: [4](#0-3) 

The endpoint is exposed as a public `#[update]` method: [5](#0-4) 

The Byzantine rejection threshold (`is_byzantine_majority_no`) requires strictly more than `f = (N-1)/3` "no" votes: [6](#0-5) 

Because resubmission resets all ballots before this threshold can be reached, the rejection path is never triggered for the attacker's proposal slot.

## Impact Explanation
A single malicious NNS node operator can keep a malicious governance-upgrade proposal alive indefinitely. While the proposal cannot be *executed* without N-f "yes" votes, it permanently occupies the attacker's proposal slot, remains visible and live, and forces all other node operators to repeatedly re-cast "no" votes after every reset. This undermines the Byzantine fault-tolerance guarantee of the root proposal rejection mechanism — a system explicitly designed to tolerate up to f malicious node operators — and constitutes a meaningful governance availability and integrity impact. This matches the **Medium** bounty impact: an attack requiring node operator control (a substantial constraint) with meaningful security impact on NNS governance.

## Likelihood Explanation
The NNS subnet has on the order of 13–40 node operators. Compromising or acting as a single malicious node operator is explicitly within the Byzantine fault model the system is designed to tolerate. The attack requires no special tooling: the attacker calls `submit_root_proposal_to_upgrade_governance_canister` (a standard ingress update) and polls `get_pending_root_proposals_to_upgrade_governance_canister` to monitor the tally. No majority, no admin key, no threshold corruption is needed. **Likelihood: Medium.**

## Recommendation
Once a proposal from a given principal has received any non-proposer ballot, disallow replacement until the proposal is accepted, rejected, or expired. A simpler mitigation is to enforce a minimum resubmission interval equal to `MAX_TIME_FOR_GOVERNANCE_UPGRADE_ROOT_PROPOSAL` between successive submissions from the same principal. Alternatively, carry forward the highest "no" vote count ever seen for a proposal on resubmission, so that resetting ballots does not erase the rejection signal.

## Proof of Concept
```rust
// Attacker is a registered NNS node operator (principal A).
// Other node operators begin voting "no" on A's proposal.

loop {
    // Poll tally via get_pending_root_proposals_to_upgrade_governance_canister()
    let proposals = root_canister
        .get_pending_root_proposals_to_upgrade_governance_canister()
        .await;
    let my_proposal = proposals.iter().find(|p| p.proposer == attacker_principal);

    if let Some(p) = my_proposal {
        let no_votes = p.node_operator_ballots.iter()
            .filter(|(_, b)| matches!(b, RootProposalBallot::No))
            .count();
        let n = p.node_operator_ballots.len();
        let f = (n - 1) / 3;

        if no_votes >= f {
            // Reset all ballots before rejection threshold (f+1) is reached
            root_canister.submit_root_proposal_to_upgrade_governance_canister(
                current_governance_sha,
                malicious_change_canister_request,
            ).await.unwrap();
            // All previously cast "no" votes are now gone; only A's auto-yes remains
        }
    }
}
```

A deterministic integration test using PocketIC can reproduce this by: (1) registering a test principal as an NNS node operator, (2) submitting a proposal, (3) casting `f` "no" votes from other operators, (4) calling `submit_root_proposal_to_upgrade_governance_canister` again from the attacker principal, and (5) asserting that the ballot vector is reset and `is_byzantine_majority_no()` returns `false`.

### Citations

**File:** rs/nns/handlers/root/impl/src/root_proposals.rs (L127-139)
```rust
    fn is_byzantine_majority_no(&self) -> bool {
        let num_nodes = self.node_operator_ballots.len();
        let max_faults = (num_nodes - 1) / 3;
        let votes_no: usize = self
            .node_operator_ballots
            .iter()
            .map(|(_, b)| match b {
                RootProposalBallot::No => 1,
                _ => 0,
            })
            .sum();
        votes_no > max_faults
    }
```

**File:** rs/nns/handlers/root/impl/src/root_proposals.rs (L142-144)
```rust
thread_local! {
  static PROPOSALS: RefCell<BTreeMap<PrincipalId, GovernanceUpgradeRootProposal>> = const { RefCell::new(BTreeMap::new()) };
}
```

**File:** rs/nns/handlers/root/impl/src/root_proposals.rs (L244-250)
```rust
    if voted_on == 0 {
        let message = format!(
            "{LOG_PREFIX}Invalid proposal. Caller: {caller} must be among the node operators of the nns subnet."
        );
        println!("{message}");
        return Err(message);
    }
```

**File:** rs/nns/handlers/root/impl/src/root_proposals.rs (L252-278)
```rust
    PROPOSALS.with(|proposals| {
        // Check whether there is a previous proposal from the same principal and log
        // that we'll be replacing it.
        if let Some(previous_proposal_from_the_same_principal) = proposals.borrow().get(&caller) {
            println!(
                "{LOG_PREFIX}Current root proposal {previous_proposal_from_the_same_principal:?} from {caller} is going to be overwritten.",
            );
        }

        // Store the proposal, the current list of principals that can vote,
        // together with the version number and as many votes for 'yes' as the
        // number of nodes the caller's principal operates, in the nns subnetwork.
        let proposed_wasm_sha = ic_crypto_sha2::Sha256::hash(&request.wasm_module).to_vec();

        proposals.borrow_mut().insert(
            caller,
            GovernanceUpgradeRootProposal {
                nns_subnet_id,
                current_wasm_sha: current_governance_wasm_sha.clone(),
                proposed_wasm_sha: proposed_wasm_sha.clone(),
                payload: request,
                proposer: caller,
                node_operator_ballots,
                subnet_membership_registry_version,
                submission_timestamp_seconds: now,
            },
        );
```

**File:** rs/nns/handlers/root/impl/src/root_proposals.rs (L331-341)
```rust
        if now
            > (proposal.submission_timestamp_seconds + MAX_TIME_FOR_GOVERNANCE_UPGRADE_ROOT_PROPOSAL)
        {
            proposals.remove(&proposer);
            let message = format!(
                "{LOG_PREFIX}Current root governance upgrade proposal from {proposer} is too old.\
                 Deleting.",
            );
            println!("{message}");
            return Err(message);
        }
```

**File:** rs/nns/handlers/root/impl/canister/canister.rs (L100-111)
```rust
#[update(hidden = true)]
async fn submit_root_proposal_to_upgrade_governance_canister(
    expected_governance_wasm_sha: serde_bytes::ByteBuf,
    proposal: ChangeCanisterRequest,
) -> Result<(), String> {
    ic_nns_handler_root::root_proposals::submit_root_proposal_to_upgrade_governance_canister(
        caller(),
        expected_governance_wasm_sha.to_vec(),
        proposal,
    )
    .await
}
```
