# Q1904: linear-interpolate via redeem: route a victim's mandatory payout through a principal that

## Question
Does `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) let an unprivileged attacker who controls the gap between the `assets` var and the real balance reach `linear-interpolate` (mainnet/contracts/vault/v0-vault-stx.clar:221) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it interpolates between two points, dividing by `(- x2 x1)`, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:221` -> `linear-interpolate`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: the gap between the `assets` var and the real balance
- Exploit idea: `linear-interpolate` interpolates between two points, dividing by `(- x2 x1)`. Reach it through `redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `redeem` twice with the gap between the `assets` var and the real balance varied, and assert that the value `linear-interpolate` returns is identical in both runs; a divergence confirms the finding.
