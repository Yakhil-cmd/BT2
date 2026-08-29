# Q4503: find-superset via collateral-add: route a victim's mandatory payout through a principal that

## Question
`find-superset` (mainnet/contracts/registry/v0-egroup.clar:262) returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest. Can an unprivileged caller of `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), by choosing the `ft` trait principal, use that to route a victim's mandatory payout through a principal that always rejects delivery, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:262` -> `find-superset`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `find-superset` returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest. Reach it through `collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `find-superset` touches, run `collateral-add` with the `ft` trait principal, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
