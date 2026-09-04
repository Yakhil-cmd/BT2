# Q0964: all_outputs_burn: sBTC reward paid exceeds reward earned

## Question
Can an unprivileged attacker reach `all_outputs_burn` (in `stackslib/src/chainstate/burn/operations/leader_block_commit.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `compute-earned-rewards` uses a per-token snapshot the claimer advances before claiming, breaking the invariant that sBTC paid for a (signer,staker,cycle) == rewards actually earned, once — leading to theft of sBTC rewards?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/leader_block_commit.rs` -> `all_outputs_burn`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `compute-earned-rewards` uses a per-token snapshot the claimer advances before claiming
- Invariant to test: sBTC paid for a (signer,staker,cycle) == rewards actually earned, once
- Expected Immunefi impact: Critical - theft of sBTC rewards
- Fast validation: test claim vs earned snapshot
