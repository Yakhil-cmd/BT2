# Q2844: unpack-u16 via liquidate: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `debt-amount` reach `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it unpacks eight u16 curve fields from one packed word, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `liquidate` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `debt-amount` across its boundary values through `liquidate` in simnet and assert `unpack-u16` never returns a value that breaks the invariant.
