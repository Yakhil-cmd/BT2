# Q0515: pox_lock_v3: a bond period folded twice in claim-rewards

## Question
Can an unprivileged attacker reach `pox_lock_v3` (in `pox-locking/src/pox_3.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that a duplicate entry in the `(list 6 uint)` folds one reward twice, breaking the invariant that reward counted per bond period == once — leading to double-paid rewards?

## Target
- File/function: `pox-locking/src/pox_3.rs` -> `pox_lock_v3`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: a duplicate entry in the `(list 6 uint)` folds one reward twice
- Invariant to test: reward counted per bond period == once
- Expected Immunefi impact: Critical - double-paid rewards
- Fast validation: test claim with a duplicated bond period
