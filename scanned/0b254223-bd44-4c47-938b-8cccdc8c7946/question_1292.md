# Q1292: collateral-remove via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `min-collateral-expected` reach `collateral-remove` (mainnet/contracts/market/v0-market-vault.clar:406) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it decrements the map and writes the entry before `send-tokens` executes, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:406` -> `collateral-remove`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `collateral-remove` decrements the map and writes the entry before `send-tokens` executes. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `min-collateral-expected` varied, and assert that the value `collateral-remove` returns is identical in both runs; a divergence confirms the finding.
