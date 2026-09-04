# Q0265: parse_pox_extend_result: claim-rewards updates last-accounted after the transfer

## Question
Can an unprivileged attacker reach `parse_pox_extend_result` (in `pox-locking/src/pox_2.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `last-accounted-rewards-only` is decremented after sBTC leaves, enabling a re-read, breaking the invariant that the accounted total == outstanding unclaimed rewards — leading to reward re-claim?

## Target
- File/function: `pox-locking/src/pox_2.rs` -> `parse_pox_extend_result`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `last-accounted-rewards-only` is decremented after sBTC leaves, enabling a re-read
- Invariant to test: the accounted total == outstanding unclaimed rewards
- Expected Immunefi impact: Critical - reward re-claim
- Fast validation: test the transfer/update ordering
