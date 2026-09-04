# Q0612: pox_lock_extend_v4: unstake-sbtc withdraws more than staked

## Question
Can an unprivileged attacker reach `pox_lock_extend_v4` (in `pox-locking/src/pox_4.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `new-amount-sats` accounting releases custody still counted for rewards, breaking the invariant that sBTC withdrawn + still-custodied == sBTC originally staked — leading to theft of custodied sBTC?

## Target
- File/function: `pox-locking/src/pox_4.rs` -> `pox_lock_extend_v4`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `new-amount-sats` accounting releases custody still counted for rewards
- Invariant to test: sBTC withdrawn + still-custodied == sBTC originally staked
- Expected Immunefi impact: Critical - theft of custodied sBTC
- Fast validation: test an unstake asserting custody conservation
