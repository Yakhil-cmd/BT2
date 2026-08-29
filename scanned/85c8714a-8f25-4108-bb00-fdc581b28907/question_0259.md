# Q0259: write-feeds via supply-collateral-add: reprice every other holder's collateral in the same transa

## Question
`write-feeds` (mainnet/contracts/market/v0-4-market.clar:149) folds up to three attacker-supplied buffers through `write-feed` with a `(response bool uint)` accumulator. Can an unprivileged caller of `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), by choosing vault share price at the moment of the deposit leg, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:149` -> `write-feeds`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: vault share price at the moment of the deposit leg
- Exploit idea: `write-feeds` folds up to three attacker-supplied buffers through `write-feed` with a `(response bool uint)` accumulator. Reach it through `supply-collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `supply-collateral-add` with vault share price at the moment of the deposit leg, then read `write-feeds` state before and after in the same block and assert the two sides of the invariant are equal.
