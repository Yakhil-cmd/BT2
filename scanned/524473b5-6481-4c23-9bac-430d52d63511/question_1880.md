# Q1880: linear-interpolate via collateral-remove-redeem: make a victim's position resolve to a worse efficiency gro

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls `amount` used for BOTH the collateral removal and the share redemption reach `linear-interpolate` (mainnet/contracts/vault/v0-vault-stx.clar:221) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it interpolates between two points, dividing by `(- x2 x1)`, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:221` -> `linear-interpolate`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `amount` used for BOTH the collateral removal and the share redemption
- Exploit idea: `linear-interpolate` interpolates between two points, dividing by `(- x2 x1)`. Reach it through `collateral-remove-redeem` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `collateral-remove-redeem` twice with `amount` used for BOTH the collateral removal and the share redemption varied, and assert that the value `linear-interpolate` returns is identical in both runs; a divergence confirms the finding.
