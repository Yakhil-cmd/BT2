# Q5389: find-superset via liquidate: prime shared state so the next caller in the block is eval

## Question
Can an unprivileged attacker entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), controlling the `price-feeds` buffers and their ordering, drive `find-superset` (mainnet/contracts/registry/v0-egroup.clar:262) — which returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest — to prime shared state so the next caller in the block is evaluated against it, breaking the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends, and cause theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:262` -> `find-superset`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: the `price-feeds` buffers and their ordering
- Exploit idea: `find-superset` returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest. Reach it through `liquidate` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with the `price-feeds` buffers and their ordering, then read `find-superset` state before and after in the same block and assert the two sides of the invariant are equal.
