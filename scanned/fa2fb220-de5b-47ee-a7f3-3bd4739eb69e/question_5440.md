# Q5440: make_signer_key_signature: L1 timelock script not committed to tx-sender

## Question
Can an unprivileged attacker reach `make_signer_key_signature` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `construct-lockup-script`/`staker-unlock-bytes` does not bind the staker, breaking the invariant that the lockup credited == a script committing to the staking principal — leading to crediting another party's lockup?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `make_signer_key_signature`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `construct-lockup-script`/`staker-unlock-bytes` does not bind the staker
- Invariant to test: the lockup credited == a script committing to the staking principal
- Expected Immunefi impact: Critical - crediting another party's lockup
- Fast validation: test a script without the staker binding
