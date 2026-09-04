# Q5150: make_pox_4_lockup: transfer-stx op with sender==recipient slips the check

## Question
Can an unprivileged attacker reach `make_pox_4_lockup` (in `stackslib/src/chainstate/stacks/boot/mod.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `check` fails to reject a self-referential transfer, breaking the invariant that every applied transfer-stx == sender != recipient — leading to accounting anomaly / stuck STX?

## Target
- File/function: `stackslib/src/chainstate/stacks/boot/mod.rs` -> `make_pox_4_lockup`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `check` fails to reject a self-referential transfer
- Invariant to test: every applied transfer-stx == sender != recipient
- Expected Immunefi impact: High - accounting anomaly / stuck STX
- Fast validation: test a self-transfer op
