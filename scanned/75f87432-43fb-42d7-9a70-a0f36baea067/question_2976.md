# Q2976: get_sender_txid: reward claimed before its cycle settled

## Question
Can an unprivileged attacker reach `get_sender_txid` (in `stackslib/src/chainstate/burn/operations/vote_for_aggregate_key.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that a cycle is claimed before settlement finalises its per-token value, breaking the invariant that rewards claimable for a cycle == rewards settled for it — leading to premature/unbacked reward?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/vote_for_aggregate_key.rs` -> `get_sender_txid`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: a cycle is claimed before settlement finalises its per-token value
- Invariant to test: rewards claimable for a cycle == rewards settled for it
- Expected Immunefi impact: Critical - premature/unbacked reward
- Fast validation: test claiming an unsettled cycle
