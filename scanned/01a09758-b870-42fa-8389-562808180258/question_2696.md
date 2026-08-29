# Q2696: calc-index-next via liquidate: seize from a position that is solvent under the mask its o

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `collateral-receiver` reach `calc-index-next` (mainnet/contracts/vault/v0-vault-stx.clar:183) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it applies a multiplier to the current index, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:183` -> `calc-index-next`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `calc-index-next` applies a multiplier to the current index. Reach it through `liquidate` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `collateral-receiver` varied, and assert that the value `calc-index-next` returns is identical in both runs; a divergence confirms the finding.
