# Q2430: new_bounded rounding drift is attacker-directed (evicting_sender.rs)

## Question
Can an unprivileged attacker entering through raw QUIC/UDP packets and transaction batches sent by an unstaked client to the leader's public TPU port reach `new_bounded` in `streamer/src/evicting_sender.rs` with a declared cost far below the real cost of the work requested, and make every rounding step inside `new_bounded` land in the attacker's favour across repeated calls, so that the invariant "Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift." breaks and the result is Loss of Funds?

## Target
- File/function: `streamer/src/evicting_sender.rs` -> `new_bounded()` (around line 31)
- Entrypoint: raw QUIC/UDP packets and transaction batches sent by an unstaked client to the leader's public TPU port
- Attacker controls: a declared cost far below the real cost of the work requested
- Exploit idea: Choose amounts so every rounding step in `new_bounded` lands in the attacker's favour, then repeat the flow to accumulate the drift into a withdrawable balance.
- Invariant to test: Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Loop the operation N times in a unit test with adversarial amounts and assert the attacker's net balance never increases.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
