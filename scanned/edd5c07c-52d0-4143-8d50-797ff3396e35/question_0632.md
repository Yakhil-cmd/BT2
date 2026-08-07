# Q0632: calculate_stake_points_for_tower rounding drift is attacker-directed (points.rs)

## Question
Can an unprivileged attacker entering through a transaction that lands in a block and is replayed by every node on the cluster reach `calculate_stake_points_for_tower` in `runtime/src/inflation_rewards/points.rs` with values chosen so the arithmetic saturates, wraps, or rounds toward the attacker, and make every rounding step inside `calculate_stake_points_for_tower` land in the attacker's favour across repeated calls, so that the invariant "Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift." breaks and the result is Loss of Funds?

## Target
- File/function: `runtime/src/inflation_rewards/points.rs` -> `calculate_stake_points_for_tower()` (around line 126)
- Entrypoint: a transaction that lands in a block and is replayed by every node on the cluster
- Attacker controls: values chosen so the arithmetic saturates, wraps, or rounds toward the attacker
- Exploit idea: Choose amounts so every rounding step in `calculate_stake_points_for_tower` lands in the attacker's favour, then repeat the flow to accumulate the drift into a withdrawable balance.
- Invariant to test: Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Loop the operation N times in a unit test with adversarial amounts and assert the attacker's net balance never increases.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
