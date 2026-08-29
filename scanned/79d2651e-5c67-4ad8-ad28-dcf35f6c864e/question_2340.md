# Q2340: create via liquidate: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `debt-amount` reach `create` (mainnet/contracts/market/v0-market-vault.clar:150) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it binds a principal to a fresh numeric id, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:150` -> `create`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `create` binds a principal to a fresh numeric id. Reach it through `liquidate` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz `debt-amount` across its boundary values through `liquidate` in simnet and assert `create` never returns a value that breaks the invariant.
