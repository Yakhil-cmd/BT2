# Q2919: from_tx: L1 proof header not bound to the claimed height

## Question
Can an unprivileged attacker reach `from_tx` (in `stackslib/src/chainstate/burn/operations/vote_for_aggregate_key.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that a header for a different burn block validates inclusion at the claimed height, breaking the invariant that the header verified == the canonical burn header at that height — leading to forged inclusion proof?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/vote_for_aggregate_key.rs` -> `from_tx`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: a header for a different burn block validates inclusion at the claimed height
- Invariant to test: the header verified == the canonical burn header at that height
- Expected Immunefi impact: Critical - forged inclusion proof
- Fast validation: test a mismatched header/height
