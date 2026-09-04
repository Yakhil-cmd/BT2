# Q0051: synthesize_pox_2_or_3_event_info: delegate-stx delegates more than the sender's balance

## Question
Can an unprivileged attacker reach `synthesize_pox_2_or_3_event_info` (in `pox-locking/src/events_24.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `check` accepts `delegated_ustx` exceeding balance, breaking the invariant that delegated amount <= sender balance — leading to over-delegation?

## Target
- File/function: `pox-locking/src/events_24.rs` -> `synthesize_pox_2_or_3_event_info`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `check` accepts `delegated_ustx` exceeding balance
- Invariant to test: delegated amount <= sender balance
- Expected Immunefi impact: High - over-delegation
- Fast validation: test an over-balance delegate op
