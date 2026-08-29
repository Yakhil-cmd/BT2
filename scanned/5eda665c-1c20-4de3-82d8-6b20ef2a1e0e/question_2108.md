# Q2108: interest-rate via liquidate-redeem: seize from a position that is solvent under the mask its o

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the redemption receiver reach `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it interpolates the packed curve at the current utilization, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the redemption receiver
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `liquidate-redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `liquidate-redeem` twice with the redemption receiver varied, and assert that the value `interest-rate` returns is identical in both runs; a divergence confirms the finding.
