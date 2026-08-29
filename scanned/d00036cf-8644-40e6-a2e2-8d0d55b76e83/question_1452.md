# Q1452: write-feed via liquidate: reprice every other holder's collateral in the same transa

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `borrower`, any third-party principal reach `write-feed` (mainnet/contracts/market/v0-4-market.clar:129) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it applies one Pyth price-feed update and folds its status, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:129` -> `write-feed`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `borrower`, any third-party principal
- Exploit idea: `write-feed` applies one Pyth price-feed update and folds its status. Reach it through `liquidate` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `borrower`, any third-party principal across its boundary values through `liquidate` in simnet and assert `write-feed` never returns a value that breaks the invariant.
