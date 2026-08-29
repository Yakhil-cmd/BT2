# Q1328: remove-user-collateral via collateral-remove-redeem: seize from a position that is solvent under the mask its o

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls the zToken/underlying id mapping reached (the u100 sentinel branch) reach `remove-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:205) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it asserts sufficiency then `map-delete`s only on an exact zero, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:205` -> `remove-user-collateral`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: the zToken/underlying id mapping reached (the u100 sentinel branch)
- Exploit idea: `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero. Reach it through `collateral-remove-redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `collateral-remove-redeem` twice with the zToken/underlying id mapping reached (the u100 sentinel branch) varied, and assert that the value `remove-user-collateral` returns is identical in both runs; a divergence confirms the finding.
