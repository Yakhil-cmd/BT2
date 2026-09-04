# Q0602: pox_lock_extend_v4: stake rollover locks a different amount than the response tuple

## Question
Can an unprivileged attacker reach `pox_lock_extend_v4` (in `pox-locking/src/pox_4.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `handle_stake_on_locked_account` rolls forward a higher/lower amount than Clarity returned, breaking the invariant that the amount locked == the amount in the pox-5 response tuple — leading to lock/commit mismatch?

## Target
- File/function: `pox-locking/src/pox_4.rs` -> `pox_lock_extend_v4`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `handle_stake_on_locked_account` rolls forward a higher/lower amount than Clarity returned
- Invariant to test: the amount locked == the amount in the pox-5 response tuple
- Expected Immunefi impact: Critical - lock/commit mismatch
- Fast validation: test a rollover asserting tuple vs lock
