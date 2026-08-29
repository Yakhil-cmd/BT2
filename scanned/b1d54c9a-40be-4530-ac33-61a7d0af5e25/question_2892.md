# Q2892: resolve-pyth via collateral-add: seize from a position that is solvent under the mask its o

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls `amount` reach `resolve-pyth` (mainnet/contracts/market/v0-4-market.clar:312) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it reads the Pyth storage record for a 32-byte ident, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:312` -> `resolve-pyth`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `resolve-pyth` reads the Pyth storage record for a 32-byte ident. Reach it through `collateral-add` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `amount` across its boundary values through `collateral-add` in simnet and assert `resolve-pyth` never returns a value that breaks the invariant.
