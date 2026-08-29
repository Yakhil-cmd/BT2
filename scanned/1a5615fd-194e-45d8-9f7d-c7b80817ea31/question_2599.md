# Q2599: filter-out-debt-asset via collateral-add: write a stranger's ledger through an unsolicited on-behalf

## Question
`filter-out-debt-asset` (mainnet/contracts/market/v0-4-market.clar:633) rebuilds the debt list without one asset, under `as-max-len? ... u64`. Can an unprivileged caller of `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), by choosing the three `price-feeds` buffers and their order, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:633` -> `filter-out-debt-asset`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the three `price-feeds` buffers and their order
- Exploit idea: `filter-out-debt-asset` rebuilds the debt list without one asset, under `as-max-len? ... u64`. Reach it through `collateral-add` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-add` with the three `price-feeds` buffers and their order, then read `filter-out-debt-asset` state before and after in the same block and assert the two sides of the invariant are equal.
