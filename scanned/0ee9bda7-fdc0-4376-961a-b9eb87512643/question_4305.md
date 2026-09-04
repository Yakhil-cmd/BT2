# Q4305: get_total_ustx_stacked: missed-unlock handler skips an account permanently

## Question
Can an unprivileged attacker reach `get_total_ustx_stacked` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `handle_pox_cycle_missed_unlocks` leaves an account locked forever, breaking the invariant that every locked account unlocks at its committed height — leading to permanent freeze of staked STX?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `get_total_ustx_stacked`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `handle_pox_cycle_missed_unlocks` leaves an account locked forever
- Invariant to test: every locked account unlocks at its committed height
- Expected Immunefi impact: Critical - permanent freeze of staked STX
- Fast validation: test a missed-unlock scenario
