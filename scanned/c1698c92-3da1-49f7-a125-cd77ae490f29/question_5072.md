# Q5072: make_pox_4_delegate_stx: stake rollover locks a different amount than the response tuple

## Question
Can an unprivileged attacker reach `make_pox_4_delegate_stx` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `handle_stake_on_locked_account` rolls forward a higher/lower amount than Clarity returned, breaking the invariant that the amount locked == the amount in the pox-5 response tuple — leading to lock/commit mismatch?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `make_pox_4_delegate_stx`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `handle_stake_on_locked_account` rolls forward a higher/lower amount than Clarity returned
- Invariant to test: the amount locked == the amount in the pox-5 response tuple
- Expected Immunefi impact: Critical - lock/commit mismatch
- Fast validation: test a rollover asserting tuple vs lock
