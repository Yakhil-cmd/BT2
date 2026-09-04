# Q0363: pox_lock_increase_v2: error response swallowed so Clarity succeeds but no lock is written

## Question
Can an unprivileged attacker reach `pox_lock_increase_v2` (in `pox-locking/src/pox_2.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `locking_error_to_vm_error` maps a failure so the call returns ok with no lock, breaking the invariant that a successful stake == a written STX lock — leading to stacking weight without locked STX?

## Target
- File/function: `pox-locking/src/pox_2.rs` -> `pox_lock_increase_v2`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `locking_error_to_vm_error` maps a failure so the call returns ok with no lock
- Invariant to test: a successful stake == a written STX lock
- Expected Immunefi impact: Critical - stacking weight without locked STX
- Fast validation: test an error path asserting ok-result vs lock presence
