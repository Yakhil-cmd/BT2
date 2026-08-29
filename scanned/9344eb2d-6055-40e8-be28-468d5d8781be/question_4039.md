# Q4039: process-collateral-asset via liquidate: seize from a position that is solvent under the mask its o

## Question
`process-collateral-asset` (mainnet/contracts/market/v0-4-market.clar:789) computes expected collateral, then caps it at the borrower's balance. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing which collateral and debt asset pair is targeted, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:789` -> `process-collateral-asset`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: which collateral and debt asset pair is targeted
- Exploit idea: `process-collateral-asset` computes expected collateral, then caps it at the borrower's balance. Reach it through `liquidate` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with which collateral and debt asset pair is targeted, then read `process-collateral-asset` state before and after in the same block and assert the two sides of the invariant are equal.
