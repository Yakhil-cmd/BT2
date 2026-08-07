# Q3530: build_updated_stake_reward rounding drift is attacker-directed (distribution.rs)

## Question
Can an unprivileged attacker entering through a transaction that lands in a block and is replayed by every node on the cluster reach `build_updated_stake_reward` in `runtime/src/bank/partitioned_epoch_rewards/distribution.rs` with a value large enough that an intermediate product overflows before the final divide, and make every rounding step inside `build_updated_stake_reward` land in the attacker's favour across repeated calls, so that the invariant "Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift." breaks and the result is Loss of Funds?

## Target
- File/function: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs` -> `build_updated_stake_reward()` (around line 239)
- Entrypoint: a transaction that lands in a block and is replayed by every node on the cluster
- Attacker controls: a value large enough that an intermediate product overflows before the final divide
- Exploit idea: Choose amounts so every rounding step in `build_updated_stake_reward` lands in the attacker's favour, then repeat the flow to accumulate the drift into a withdrawable balance.
- Invariant to test: Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Loop the operation N times in a unit test with adversarial amounts and assert the attacker's net balance never increases.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
