# Q3621: as_waterfall: delegate-stx delegates more than the sender's balance

## Question
Can an unprivileged attacker reach `as_waterfall` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `check` accepts `delegated_ustx` exceeding balance, breaking the invariant that delegated amount <= sender balance — leading to over-delegation?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `as_waterfall`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `check` accepts `delegated_ustx` exceeding balance
- Invariant to test: delegated amount <= sender balance
- Expected Immunefi impact: High - over-delegation
- Fast validation: test an over-balance delegate op
