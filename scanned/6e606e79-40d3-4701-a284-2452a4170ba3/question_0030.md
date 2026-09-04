# Q0030: synthesize_pox_event_info: clamp mis-bounds first-changed-reward-cycle

## Question
Can an unprivileged attacker reach `synthesize_pox_event_info` (in `pox-locking/src/events.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `clamp` excludes the current cycle so custody is released while still counted, breaking the invariant that cycles adjusted == exactly the affected cycle range — leading to reward/custody desync?

## Target
- File/function: `pox-locking/src/events.rs` -> `synthesize_pox_event_info`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `clamp` excludes the current cycle so custody is released while still counted
- Invariant to test: cycles adjusted == exactly the affected cycle range
- Expected Immunefi impact: Critical - reward/custody desync
- Fast validation: test the clamp boundary
