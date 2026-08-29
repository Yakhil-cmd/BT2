# Q4579: merge-price via supply-collateral-add: write a stranger's ledger through an unsolicited on-behalf

## Question
`merge-price` (mainnet/contracts/market/v0-4-market.clar:506) attaches a price to an asset record by position in the fold, not by asset id. Can an unprivileged caller of `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), by choosing the `ft` trait principal deciding which vault is routed to, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal deciding which vault is routed to
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `supply-collateral-add` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `supply-collateral-add` with the `ft` trait principal deciding which vault is routed to, then read `merge-price` state before and after in the same block and assert the two sides of the invariant are equal.
