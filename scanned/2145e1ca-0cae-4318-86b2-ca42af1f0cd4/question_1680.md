# Q1680: next-index via collateral-remove-redeem: route a victim's mandatory payout through a principal that

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls `amount` used for BOTH the collateral removal and the share redemption reach `next-index` (mainnet/contracts/vault/v0-vault-stx.clar:379) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it returns the stale `index` unchanged when the accrue pause state is set, instead of reverting, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:379` -> `next-index`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `amount` used for BOTH the collateral removal and the share redemption
- Exploit idea: `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting. Reach it through `collateral-remove-redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `amount` used for BOTH the collateral removal and the share redemption across its boundary values through `collateral-remove-redeem` in simnet and assert `next-index` never returns a value that breaks the invariant.
