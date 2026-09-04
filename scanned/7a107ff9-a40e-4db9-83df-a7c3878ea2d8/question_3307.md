# Q3307: pox_5_sbtc_contract: reentrancy through validate-stake! double-counts a commitment

## Question
Can an unprivileged attacker reach `pox_5_sbtc_contract` (in `stackslib/src/chainstate/nakamoto/signer_set.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that the attacker's signer-manager re-enters pox-5 while it is mid-mutation before the guard covers the section, breaking the invariant that times a commitment/reward is counted per tx == one — leading to double stake/claim?

## Target
- File/function: `stackslib/src/chainstate/nakamoto/signer_set.rs` -> `pox_5_sbtc_contract`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: the attacker's signer-manager re-enters pox-5 while it is mid-mutation before the guard covers the section
- Invariant to test: times a commitment/reward is counted per tx == one
- Expected Immunefi impact: Critical - double stake/claim
- Fast validation: test a re-entrant signer-manager asserting count
