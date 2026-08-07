# Q2804: token_amount_to_ui_amount_v3 rounding drift is attacker-directed (parse_token.rs)

## Question
Can an unprivileged attacker entering through one JSON-RPC call or websocket subscription from a single client, at most once per CLUSTER_SLOT_TIME_TARGET/2 reach `token_amount_to_ui_amount_v3` in `account-decoder/src/parse_token.rs` with a value large enough that an intermediate product overflows before the final divide, and make every rounding step inside `token_amount_to_ui_amount_v3` land in the attacker's favour across repeated calls, so that the invariant "Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift." breaks and the result is Loss of Funds?

## Target
- File/function: `account-decoder/src/parse_token.rs` -> `token_amount_to_ui_amount_v3()` (around line 125)
- Entrypoint: one JSON-RPC call or websocket subscription from a single client, at most once per CLUSTER_SLOT_TIME_TARGET/2
- Attacker controls: a value large enough that an intermediate product overflows before the final divide
- Exploit idea: Choose amounts so every rounding step in `token_amount_to_ui_amount_v3` lands in the attacker's favour, then repeat the flow to accumulate the drift into a withdrawable balance.
- Invariant to test: Rounding is either exact or always rounds against the caller, and repeated operations cannot accumulate a positive drift.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Loop the operation N times in a unit test with adversarial amounts and assert the attacker's net balance never increases.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
