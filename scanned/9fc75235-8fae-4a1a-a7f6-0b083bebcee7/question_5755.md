# Q5755: call-liquidate via liquidate: reprice every other holder's collateral in the same transa

## Question
`call-liquidate` (mainnet/contracts/market/v0-4-market.clar:907) invokes `liquidate` with `none` for price-feeds, so a whole batch shares one snapshot. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing the `price-feeds` buffers and their ordering, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:907` -> `call-liquidate`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: the `price-feeds` buffers and their ordering
- Exploit idea: `call-liquidate` invokes `liquidate` with `none` for price-feeds, so a whole batch shares one snapshot. Reach it through `liquidate` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with the `price-feeds` buffers and their ordering, then read `call-liquidate` state before and after in the same block and assert the two sides of the invariant are equal.
