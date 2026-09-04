# Q3288: pox_5_pause_admin: signer-grant domain omits chain-id

## Question
Can an unprivileged attacker reach `pox_5_pause_admin` (in `stackslib/src/chainstate/nakamoto/signer_set.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `POX_5_SIGNER_DOMAIN` lets a testnet/other-chain signature validate, breaking the invariant that every signer signature == valid for exactly one chain — leading to cross-chain signature reuse?

## Target
- File/function: `stackslib/src/chainstate/nakamoto/signer_set.rs` -> `pox_5_pause_admin`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `POX_5_SIGNER_DOMAIN` lets a testnet/other-chain signature validate
- Invariant to test: every signer signature == valid for exactly one chain
- Expected Immunefi impact: High - cross-chain signature reuse
- Fast validation: test a signature from another chain-id
