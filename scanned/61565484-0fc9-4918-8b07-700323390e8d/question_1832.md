# Q1832: debt-remove-scaled via liquidate-multi: seize from a position that is solvent under the mask its o

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the full batch list and its ordering reach `debt-remove-scaled` (mainnet/contracts/market/v0-market-vault.clar:473) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it clears the debt bit only when the remaining scaled debt is exactly zero, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:473` -> `debt-remove-scaled`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the full batch list and its ordering
- Exploit idea: `debt-remove-scaled` clears the debt bit only when the remaining scaled debt is exactly zero. Reach it through `liquidate-multi` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with the full batch list and its ordering varied, and assert that the value `debt-remove-scaled` returns is identical in both runs; a divergence confirms the finding.
