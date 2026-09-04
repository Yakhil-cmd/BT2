# Q2774: from_tx: STX unlocks earlier than the committed height

## Question
Can an unprivileged attacker reach `from_tx` (in `stackslib/src/chainstate/burn/operations/transfer_stx.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `num-cycles`/`unlock-cycle` overflow or a start height in the past shortens the lock, breaking the invariant that unlock burn height == the height the accepted stake committed — leading to early unlock of locked STX?

## Target
- File/function: `stackslib/src/chainstate/burn/operations/transfer_stx.rs` -> `from_tx`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `num-cycles`/`unlock-cycle` overflow or a start height in the past shortens the lock
- Invariant to test: unlock burn height == the height the accepted stake committed
- Expected Immunefi impact: Critical - early unlock of locked STX
- Fast validation: test an overflowing num-cycles
