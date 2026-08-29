# Q5499: collateral-remove via collateral-remove: write a stranger's ledger through an unsolicited on-behalf

## Question
`collateral-remove` (mainnet/contracts/market/v0-market-vault.clar:406) decrements the map and writes the entry before `send-tokens` executes. Can an unprivileged caller of `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), by choosing `receiver`, including a contract principal, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing temporary freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:406` -> `collateral-remove`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: `receiver`, including a contract principal
- Exploit idea: `collateral-remove` decrements the map and writes the entry before `send-tokens` executes. Reach it through `collateral-remove` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Snapshot every state variable `collateral-remove` touches, run `collateral-remove` with `receiver`, including a contract principal, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
