# Q2156: process-collateral-asset via liquidate-redeem: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the redemption receiver reach `process-collateral-asset` (mainnet/contracts/market/v0-4-market.clar:789) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it computes expected collateral, then caps it at the borrower's balance, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:789` -> `process-collateral-asset`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the redemption receiver
- Exploit idea: `process-collateral-asset` computes expected collateral, then caps it at the borrower's balance. Reach it through `liquidate-redeem` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate-redeem` twice with the redemption receiver varied, and assert that the value `process-collateral-asset` returns is identical in both runs; a divergence confirms the finding.
