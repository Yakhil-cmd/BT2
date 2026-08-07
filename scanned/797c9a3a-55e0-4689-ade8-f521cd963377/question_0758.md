# Q0758: to_budget rounding drift is attacker-directed (compute_budget.rs)

## Question
Can an unprivileged attacker entering through a transaction broadcast to a public TPU/QUIC endpoint by an ordinary funded keypair reach `to_budget` in `compute-budget/src/compute_budget.rs` with a value that makes the limit computation itself overflow into a larger allowance, and make every rounding step inside `to_budget` land in the attacker's favour across repeated calls, so that the invariant "Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift." breaks and the result is Loss of Funds?

## Target
- File/function: `compute-budget/src/compute_budget.rs` -> `to_budget()` (around line 237)
- Entrypoint: a transaction broadcast to a public TPU/QUIC endpoint by an ordinary funded keypair
- Attacker controls: a value that makes the limit computation itself overflow into a larger allowance
- Exploit idea: Choose amounts so every rounding step in `to_budget` lands in the attacker's favour, then repeat the flow to accumulate the drift into a withdrawable balance.
- Invariant to test: Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Loop the operation N times in a unit test with adversarial amounts and assert the attacker's net balance never increases.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
