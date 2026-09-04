# Q5696: new: settle-staker-rewards zeroes state after transfer

## Question
Can an unprivileged attacker reach `new` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that the unclaimed map is zeroed post-transfer so a reentrant path reads the old value, breaking the invariant that unclaimed after settle == zero before any further transfer — leading to double settlement?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `new`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: the unclaimed map is zeroed post-transfer so a reentrant path reads the old value
- Invariant to test: unclaimed after settle == zero before any further transfer
- Expected Immunefi impact: Critical - double settlement
- Fast validation: test a reentrant settle
