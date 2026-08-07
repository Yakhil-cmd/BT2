# Q3066: staked_nodes authorization check bypassed (vote_account.rs)

## Question
Can an unprivileged attacker entering through a system/stake/vote instruction sent by an ordinary funded keypair, directly or via CPI reach `staked_nodes` in `vote/src/vote_account.rs` with a maximal instruction/account count that pushes the path to its declared limit, and have the state change applied even though the authority stored in the target account never signed, so that the invariant "Every state change requires the signature of the authority stored in the account being changed." breaks and the result is Loss of Funds?

## Target
- File/function: `vote/src/vote_account.rs` -> `staked_nodes()` (around line 176)
- Entrypoint: a system/stake/vote instruction sent by an ordinary funded keypair, directly or via CPI
- Attacker controls: a maximal instruction/account count that pushes the path to its declared limit
- Exploit idea: Reach `staked_nodes` on an account the attacker does not own and get the write applied anyway, because the check consumes a different value than the mutation does.
- Invariant to test: Every state change requires the signature of the authority stored in the account being changed.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Unit test in `vote/src/vote_account.rs`: build the instruction with a victim account and an attacker signer; assert the call returns an error and the victim account bytes are unchanged.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
