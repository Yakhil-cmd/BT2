# Q3340: pox_5_sbtc_registry_contract: L1 timelock script not committed to tx-sender

## Question
Can an unprivileged attacker reach `pox_5_sbtc_registry_contract` (in `stackslib/src/chainstate/nakamoto/signer_set.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `construct-lockup-script`/`staker-unlock-bytes` does not bind the staker, breaking the invariant that the lockup credited == a script committing to the staking principal — leading to crediting another party's lockup?

## Target
- File/function: `stackslib/src/chainstate/nakamoto/signer_set.rs` -> `pox_5_sbtc_registry_contract`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `construct-lockup-script`/`staker-unlock-bytes` does not bind the staker
- Invariant to test: the lockup credited == a script committing to the staking principal
- Expected Immunefi impact: Critical - crediting another party's lockup
- Fast validation: test a script without the staker binding
