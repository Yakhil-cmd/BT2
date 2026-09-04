# Q5943: with_sortdb: error response swallowed so Clarity succeeds but no lock is written

## Question
Can an unprivileged attacker reach `with_sortdb` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `locking_error_to_vm_error` maps a failure so the call returns ok with no lock, breaking the invariant that a successful stake == a written STX lock — leading to stacking weight without locked STX?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `with_sortdb`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `locking_error_to_vm_error` maps a failure so the call returns ok with no lock
- Invariant to test: a successful stake == a written STX lock
- Expected Immunefi impact: Critical - stacking weight without locked STX
- Fast validation: test an error path asserting ok-result vs lock presence
