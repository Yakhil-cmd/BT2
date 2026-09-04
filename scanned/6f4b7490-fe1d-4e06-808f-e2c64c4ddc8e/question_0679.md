# Q0679: pox_lock_v4: burnchain stack-stx locks STX the derived sender did not authorise

## Question
Can an unprivileged attacker reach `pox_lock_v4` (in `pox-locking/src/pox_4.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `parse_from_tx` derives the sender from a Bitcoin input and locks with defaulted fields, breaking the invariant that STX locked by an op == STX owned by the mapped Stacks address with its committed params — leading to unauthorised lock via burn op?

## Target
- File/function: `pox-locking/src/pox_4.rs` -> `pox_lock_v4`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `parse_from_tx` derives the sender from a Bitcoin input and locks with defaulted fields
- Invariant to test: STX locked by an op == STX owned by the mapped Stacks address with its committed params
- Expected Immunefi impact: Critical - unauthorised lock via burn op
- Fast validation: test a crafted StackStxOp
