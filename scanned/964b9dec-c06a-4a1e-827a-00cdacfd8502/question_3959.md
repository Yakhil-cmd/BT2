# Q3959: oracle-last-update via collateral-remove: push a third party's position past a fold bound so every e

## Question
`oracle-last-update` (mainnet/contracts/market/v0-4-market.clar:939) returns the stored monotonic timestamp for a `{type, ident}` key shared by every asset using that feed. Can an unprivileged caller of `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), by choosing the `ft` trait principal, use that to push a third party's position past a fold bound so every evaluation of it aborts, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing permanent freezing of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:939` -> `oracle-last-update`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `oracle-last-update` returns the stored monotonic timestamp for a `{type, ident}` key shared by every asset using that feed. Reach it through `collateral-remove` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Run the baseline `collateral-remove` call, then the attacker-shaped one with the `ft` trait principal, and assert the attacker's net token balance change is zero or negative.
