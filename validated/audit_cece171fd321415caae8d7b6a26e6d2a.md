Audit Report

## Title
SNS Governance Lacks Voting Power Spike Detection at Proposal Creation, Enabling Last-Minute Stake Inflation to Manipulate Ballot Weights — (File: `rs/sns/governance/src/governance.rs`)

## Summary
SNS governance's `compute_ballots_for_new_proposal` captures live neuron voting power at proposal creation time with no historical snapshot or spike-detection safeguard. An attacker holding an SNS neuron with sufficient dissolve delay can transfer tokens to their neuron subaccount, call `ClaimOrRefresh` to immediately inflate `cached_neuron_stake_e8s`, then create or time a proposal so that the inflated voting power is locked into every ballot. NNS governance already deploys a `VotingPowerSnapshots` mechanism that detects and rejects such spikes; SNS has no equivalent.

## Finding Description
**Root cause — SNS `compute_ballots_for_new_proposal`**

`rs/sns/governance/src/governance.rs` lines 5255–5280 iterate over every neuron at proposal-creation time and record the current live voting power directly into the ballot with no snapshot history, no spike threshold, and no fallback:

```rust
for (k, v) in self.proto.neurons.iter() {
    if v.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_for_vote {
        continue;
    }
    let voting_power = v.voting_power(now_seconds, ...);
    electoral_roll.insert(k.clone(), Ballot { vote: Vote::Unspecified, voting_power, ... });
}
```

**Stake inflation path**

`refresh_neuron` (`rs/sns/governance/src/governance.rs` lines 4237–4298) queries the ledger balance and calls `neuron.update_stake(balance.get_e8s(), now)` (lines 4287–4288), which immediately writes the new balance into `cached_neuron_stake_e8s` (`rs/sns/governance/src/neuron.rs` line 679). There is no delay, no rate limit, and no record of the prior stake level.

**Contrast — NNS `compute_ballots_for_standard_proposal`**

`rs/nns/governance/src/governance.rs` lines 5486–5533 compute a current snapshot and then call `VOTING_POWER_SNAPSHOTS.previous_ballots_if_voting_power_spike_detected(...)`. If the current total potential voting power exceeds 1.5× the minimum in the retained daily snapshots (`MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE = 1.5`, `rs/nns/governance/src/governance/voting_power_snapshots.rs` line 21), the previous (lower) snapshot is used for ballot construction instead. A grep for `VotingPowerSnapshot` scoped to `rs/sns/**` returns zero matches, confirming SNS has no equivalent mechanism.

**Exploit flow**

1. Attacker holds SNS neuron N with `dissolve_delay ≥ neuron_minimum_dissolve_delay_to_vote_seconds` and a small initial stake (e.g., 1,000 tokens).
2. Attacker transfers a large amount of SNS tokens (e.g., 20,001) to neuron N's subaccount on the SNS ledger.
3. Attacker calls `manage_neuron { ClaimOrRefresh }` → `refresh_neuron` → `update_stake` → `cached_neuron_stake_e8s` is immediately updated to 21,001 tokens.
4. Attacker creates a proposal (or times the attack to coincide with an imminent proposal).
5. `compute_ballots_for_new_proposal` captures the inflated voting power verbatim; no spike detection fires.
6. Attacker votes Yes; their inflated voting power exceeds all other voters combined.
7. Proposal is adopted (e.g., treasury transfer to attacker-controlled address).
8. Attacker calls `StartDissolving`; after the dissolve delay, disburses 21,001 tokens.

**Why existing checks are insufficient**

The only guard in `compute_ballots_for_new_proposal` is the `min_dissolve_delay_for_vote` eligibility check (line 5258), which the attacker already satisfies. There is no check on the rate of change of voting power, no comparison against historical snapshots, and no fallback path.

## Impact Explanation
An attacker can pass arbitrary SNS governance proposals — including treasury transfers, canister upgrades, and parameter changes — by temporarily acquiring a voting-power majority through stake inflation. This constitutes unauthorized access to SNS governance assets and canister-controlled funds. The impact matches the High bounty class: "Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds where exploitation requires meaningful per-target work or other constraints." The constraint is the capital required and the dissolve-delay lock-up period; for SNS DAOs controlling significant treasury assets, the attack can be economically rational.

## Likelihood Explanation
**Medium-High.** Prerequisites are: (a) an existing SNS neuron with sufficient dissolve delay (achievable by any market participant), and (b) capital sufficient to exceed the combined voting power of all other participating neurons. The attacker must lock funds for the dissolve delay period, but this cost is bounded and potentially profitable against high-value SNS treasuries. The NNS added spike detection (via `SnapshotVotingPowerTask`, `rs/nns/governance/src/timer_tasks/snapshot_voting_power.rs`) precisely because this attack vector was considered realistic enough to warrant a protocol-level fix; SNS has not received the equivalent fix. The attack is repeatable and requires no special privileges beyond neuron ownership.

## Recommendation
Implement a periodic voting-power snapshot mechanism for SNS governance mirroring the NNS design:

1. Add a `VotingPowerSnapshots` equivalent to SNS governance state, recording per-neuron deciding voting power on a regular cadence (e.g., daily, matching `VOTING_POWER_SNAPSHOT_INTERVAL = 86400s`).
2. In `compute_ballots_for_new_proposal`, compute the current total potential voting power and compare it against the minimum in the retained snapshots using the same 1.5× threshold (`MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE`).
3. If a spike is detected, construct ballots from the previous (lower) snapshot instead of the live neuron state.
4. Add a recurring timer task analogous to `SnapshotVotingPowerTask` to maintain the snapshot history.

This is the exact mitigation already deployed in NNS governance.

## Proof of Concept

```
Precondition:
  - Eve holds SNS neuron N: dissolve_delay = 1 year, cached_neuron_stake_e8s = 1,000 tokens.
  - Alice holds neuron A: 10,000 tokens staked.
  - Bob holds neuron B: 10,000 tokens staked.
  - Total voting power (simplified): Alice ~47.6%, Bob ~47.6%, Eve ~4.8%.

Step 1: Eve transfers 20,001 SNS tokens to neuron N's subaccount on the SNS ledger.

Step 2: Eve calls manage_neuron { ClaimOrRefresh { by: NeuronId(N) } }.
        → refresh_neuron (governance.rs:4237) queries ledger: balance = 21,001 tokens.
        → neuron.update_stake(21_001 * E8, now) (governance.rs:4287-4288).
        → cached_neuron_stake_e8s = 21_001 * E8 (neuron.rs:679).

Step 3: Eve calls manage_neuron { MakeProposal { TransferSnsTreasuryFunds { ... } } }.
        → compute_ballots_for_new_proposal (governance.rs:5255-5280) iterates neurons.
        → Eve's ballot.voting_power = f(21,001 tokens, 1 year dissolve, age).
        → Alice's ballot.voting_power = f(10,000 tokens, ...).
        → Bob's ballot.voting_power  = f(10,000 tokens, ...).
        → No spike detection fires (SNS has none).
        → Eve's voting power ≈ 51.2% of total.

Step 4: Eve votes Yes. Proposal is adopted (Eve > Alice + Bob).

Step 5: Treasury funds transferred to Eve's address.

Step 6: Eve calls StartDissolving on neuron N.
        After 1 year, Eve disburses 21,001 tokens.
        Net gain: treasury funds minus opportunity cost of locking 20,001 tokens for 1 year.

Verification: The same attack on NNS governance would be blocked at Step 3 because
compute_ballots_for_standard_proposal (nns/governance.rs:5506-5512) would detect
21,001 vs. historical ~1,000 tokens = >1.5× threshold and substitute the previous snapshot.
```