# Q3196: parse_vote_for_aggregate_public_key: stake-update extends a lapsed lock but changes state on error

## Question
Can an unprivileged attacker reach `parse_vote_for_aggregate_public_key` (in `stackslib/src/chainstate/nakamoto/signer_set.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `handle_stake_lockup_update_pox_v5` errors yet mutates state, breaking the invariant that state after a failed update == state before it — leading to inconsistent lock state / temporary freeze?

## Target
- File/function: `stackslib/src/chainstate/nakamoto/signer_set.rs` -> `parse_vote_for_aggregate_public_key`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `handle_stake_lockup_update_pox_v5` errors yet mutates state
- Invariant to test: state after a failed update == state before it
- Expected Immunefi impact: High - inconsistent lock state / temporary freeze
- Fast validation: test a failing stake-update
