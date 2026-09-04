# Q2533: vote_for_aggregate_key_to_json: rollover refunds old-sbtc while the new bond still custodies it

## Question
Can an unprivileged attacker reach `vote_for_aggregate_key_to_json` (in `stackslib/src/chainstate/burn/operations/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `register-for-bond` refunds `old-sbtc` on the assumption the old bond is released, breaking the invariant that sBTC held by pox-5 == sum of active memberships + reserve — leading to double-counted sBTC custody?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/mod.rs` -> `vote_for_aggregate_key_to_json`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `register-for-bond` refunds `old-sbtc` on the assumption the old bond is released
- Invariant to test: sBTC held by pox-5 == sum of active memberships + reserve
- Expected Immunefi impact: Critical - double-counted sBTC custody
- Fast validation: test a rollover asserting total custody
