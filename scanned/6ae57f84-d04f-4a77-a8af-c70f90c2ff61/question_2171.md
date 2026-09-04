# Q2171: parse_u128_from_be: duplicate outpoint double-summed in the L1 proof

## Question
Can an unprivileged attacker reach `parse_u128_from_be` (in `stackslib/src/chainstate/burn/operations/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `seen-outpoints` misses a duplicate (txid,index) so one output counts twice, breaking the invariant that sats summed == sum over distinct outpoints — leading to inflated bond credit?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/mod.rs` -> `parse_u128_from_be`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `seen-outpoints` misses a duplicate (txid,index) so one output counts twice
- Invariant to test: sats summed == sum over distinct outpoints
- Expected Immunefi impact: Critical - inflated bond credit
- Fast validation: test a proof with a repeated outpoint
