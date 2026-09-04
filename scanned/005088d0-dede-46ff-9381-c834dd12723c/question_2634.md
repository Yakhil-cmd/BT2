# Q2634: from_tx: min-ustx-for-sats-amount uses a stale ratio

## Question
Can an unprivileged attacker reach `from_tx` (in `stackslib/src/chainstate/burn/operations/stack_stx.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that sats convert to ustx at an outdated `stx-value-ratio`, breaking the invariant that the ustx-equivalent used == the ratio in effect for that bond — leading to mispriced bond weight?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/stack_stx.rs` -> `from_tx`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: sats convert to ustx at an outdated `stx-value-ratio`
- Invariant to test: the ustx-equivalent used == the ratio in effect for that bond
- Expected Immunefi impact: High - mispriced bond weight
- Fast validation: test a ratio change boundary
