# Q2808: get-position via collateral-add: seize from a position that is solvent under the mask its o

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls `amount` reach `get-position` (mainnet/contracts/market/v0-4-market.clar:466) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it returns only rows whose bit is set in the ENABLED bitmap, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:466` -> `get-position`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `get-position` returns only rows whose bit is set in the ENABLED bitmap. Reach it through `collateral-add` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz `amount` across its boundary values through `collateral-add` in simnet and assert `get-position` never returns a value that breaks the invariant.
