# Q1998: get-position via liquidate: route a victim's mandatory payout through a principal that

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `debt-amount`, can an unprivileged attacker make `get-position` (mainnet/contracts/market/v0-4-market.clar:466) route a victim's mandatory payout through a principal that always rejects delivery? `get-position` returns only rows whose bit is set in the ENABLED bitmap, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:466` -> `get-position`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `get-position` returns only rows whose bit is set in the ENABLED bitmap. Reach it through `liquidate` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz `debt-amount` across its boundary values through `liquidate` in simnet and assert `get-position` never returns a value that breaks the invariant.
