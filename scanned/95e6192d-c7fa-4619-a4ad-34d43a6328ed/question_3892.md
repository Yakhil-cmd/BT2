# Q3892: get_current_reward_cycle: reward set weight exceeds locked STX

## Question
Can an unprivileged attacker reach `get_current_reward_cycle` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `make_reward_set`/`get_threshold_from_participation` counts an unlocked staker, breaking the invariant that weight assigned for a cycle == STX locked and unexpired for it — leading to inflated signing weight?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `get_current_reward_cycle`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `make_reward_set`/`get_threshold_from_participation` counts an unlocked staker
- Invariant to test: weight assigned for a cycle == STX locked and unexpired for it
- Expected Immunefi impact: High - inflated signing weight
- Fast validation: test a stale participation total
