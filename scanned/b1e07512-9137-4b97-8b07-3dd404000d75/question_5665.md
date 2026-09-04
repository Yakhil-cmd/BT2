# Q5665: metadata_serialize: claim-rewards updates last-accounted after the transfer

## Question
Can an unprivileged attacker reach `metadata_serialize` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `last-accounted-rewards-only` is decremented after sBTC leaves, enabling a re-read, breaking the invariant that the accounted total == outstanding unclaimed rewards — leading to reward re-claim?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `metadata_serialize`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `last-accounted-rewards-only` is decremented after sBTC leaves, enabling a re-read
- Invariant to test: the accounted total == outstanding unclaimed rewards
- Expected Immunefi impact: Critical - reward re-claim
- Fast validation: test the transfer/update ordering
