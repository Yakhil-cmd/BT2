# Q5578: make_sip_031_body: unstake during prepare phase releases wrongly

## Question
Can an unprivileged attacker reach `make_sip_031_body` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that an unstake in the prepare phase releases custody counted for rewards, breaking the invariant that custody released == custody no longer earning rewards — leading to reward theft via timing?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `make_sip_031_body`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: an unstake in the prepare phase releases custody counted for rewards
- Invariant to test: custody released == custody no longer earning rewards
- Expected Immunefi impact: Critical - reward theft via timing
- Fast validation: test a prepare-phase unstake
