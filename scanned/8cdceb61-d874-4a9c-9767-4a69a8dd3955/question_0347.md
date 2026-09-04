# Q0347: pox_lock_extend_v2: signer-key grant replayed across bonds

## Question
Can an unprivileged attacker reach `pox_lock_extend_v2` (in `pox-locking/src/pox_2.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that the `used` key omits a distinguishing field so one grant authorises two actions, breaking the invariant that stacking actions authorised == one grant signed per (staker,amount,cycle,chain) — leading to unauthorised stacking via replay?

## Target
- File/function: `pox-locking/src/pox_2.rs` -> `pox_lock_extend_v2`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: the `used` key omits a distinguishing field so one grant authorises two actions
- Invariant to test: stacking actions authorised == one grant signed per (staker,amount,cycle,chain)
- Expected Immunefi impact: High - unauthorised stacking via replay
- Fast validation: test reusing a grant across bonds
