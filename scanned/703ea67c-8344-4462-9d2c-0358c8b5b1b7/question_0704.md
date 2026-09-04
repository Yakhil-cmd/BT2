# Q0704: handle_contract_call: STX unlocks earlier than the committed height

## Question
Can an unprivileged attacker reach `handle_contract_call` (in `pox-locking/src/pox_5.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `num-cycles`/`unlock-cycle` overflow or a start height in the past shortens the lock, breaking the invariant that unlock burn height == the height the accepted stake committed — leading to early unlock of locked STX?

## Target
- File/function: `pox-locking/src/pox_5.rs` -> `handle_contract_call`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `num-cycles`/`unlock-cycle` overflow or a start height in the past shortens the lock
- Invariant to test: unlock burn height == the height the accepted stake committed
- Expected Immunefi impact: Critical - early unlock of locked STX
- Fast validation: test an overflowing num-cycles
