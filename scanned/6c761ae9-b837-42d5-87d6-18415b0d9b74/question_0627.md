# Q0627: pox_lock_extend_v4: verify-not-prepare-phase bypassed for a next-cycle mutation

## Question
Can an unprivileged attacker reach `pox_lock_extend_v4` (in `pox-locking/src/pox_4.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that a path mutates next-cycle state during the prepare phase, breaking the invariant that no next-cycle mutation occurs during the prepare phase — leading to reward/weight corruption?

## Target
- File/function: `pox-locking/src/pox_4.rs` -> `pox_lock_extend_v4`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: a path mutates next-cycle state during the prepare phase
- Invariant to test: no next-cycle mutation occurs during the prepare phase
- Expected Immunefi impact: High - reward/weight corruption
- Fast validation: test a prepare-phase mutation
