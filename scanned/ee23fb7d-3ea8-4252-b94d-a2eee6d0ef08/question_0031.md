# Q0031: synthesize_pox_2_or_3_event_info: locked STX exceeds the validated commitment

## Question
Can an unprivileged attacker reach `synthesize_pox_2_or_3_event_info` (in `pox-locking/src/events_24.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that the `STXBalance` lock written by pox-locking exceeds the `amount-ustx` the pox-5 body validated against spendable balance, breaking the invariant that STX locked after the call == the amount validated against the account balance — leading to unbacked lock / accounting insolvency?

## Target
- File/function: `pox-locking/src/events_24.rs` -> `synthesize_pox_2_or_3_event_info`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: the `STXBalance` lock written by pox-locking exceeds the `amount-ustx` the pox-5 body validated against spendable balance
- Invariant to test: STX locked after the call == the amount validated against the account balance
- Expected Immunefi impact: Critical - unbacked lock / accounting insolvency
- Fast validation: booted-chainstate test asserting locked STX vs validated amount
