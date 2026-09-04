# Q3308: pox_5_sbtc_contract: L1 lockup proof credits sats never locked on Bitcoin

## Question
Can an unprivileged attacker reach `pox_5_sbtc_contract` (in `stackslib/src/chainstate/nakamoto/signer_set.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `verify-l1-lockups` sums an `amount` field that differs from the real Bitcoin output value, breaking the invariant that sats credited == sats locked in a confirmed Bitcoin timelock to the staker — leading to unbacked bond from a forged proof?

## Target
- File/function: `stackslib/src/chainstate/nakamoto/signer_set.rs` -> `pox_5_sbtc_contract`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `verify-l1-lockups` sums an `amount` field that differs from the real Bitcoin output value
- Invariant to test: sats credited == sats locked in a confirmed Bitcoin timelock to the staker
- Expected Immunefi impact: Critical - unbacked bond from a forged proof
- Fast validation: test a proof whose amount != output value
