# Q0041: synthesize_pox_2_or_3_event_info: duplicate outpoint double-summed in the L1 proof

## Question
Can an unprivileged attacker reach `synthesize_pox_2_or_3_event_info` (in `pox-locking/src/events_24.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `seen-outpoints` misses a duplicate (txid,index) so one output counts twice, breaking the invariant that sats summed == sum over distinct outpoints — leading to inflated bond credit?

## Target
- File/function: `pox-locking/src/events_24.rs` -> `synthesize_pox_2_or_3_event_info`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `seen-outpoints` misses a duplicate (txid,index) so one output counts twice
- Invariant to test: sats summed == sum over distinct outpoints
- Expected Immunefi impact: Critical - inflated bond credit
- Fast validation: test a proof with a repeated outpoint
