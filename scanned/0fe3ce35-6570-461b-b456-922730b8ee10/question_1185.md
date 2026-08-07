# Q1185: set_is_signer settles one authorization twice (instruction_accounts.rs)

## Question
Can an unprivileged attacker entering through deploying an attacker-authored sBPF program and invoking it with crafted instruction data and account lists reach `set_is_signer` in `transaction-context/src/instruction_accounts.rs` with a boundary value exactly on the accept/reject edge of the predicate, and have `set_is_signer` apply the same authorized effect a second time, so that the invariant "One signed authorization produces exactly one state effect." breaks and the result is Loss of Funds?

## Target
- File/function: `transaction-context/src/instruction_accounts.rs` -> `set_is_signer()` (around line 49)
- Entrypoint: deploying an attacker-authored sBPF program and invoking it with crafted instruction data and account lists
- Attacker controls: a boundary value exactly on the accept/reject edge of the predicate
- Exploit idea: Get `set_is_signer` to apply the same logical effect twice from a single user authorization by re-entering it or replaying the surrounding flow.
- Invariant to test: One signed authorization produces exactly one state effect.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Integration test: submit the flow twice (and once re-entrantly) and assert the second application is rejected and balances moved once.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can claim, double-claim, or redirect epoch rewards, commission, or collected fees belonging to another stake or vote account.
