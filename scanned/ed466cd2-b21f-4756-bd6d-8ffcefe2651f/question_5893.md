# Q5893: mask-pos via collateral-remove: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), controlling `amount` relative to the current collateral row (the removing-all branch), drive `mask-pos` (mainnet/contracts/market/v0-market-vault.clar:91) — which maps an asset id to a bit position, offsetting debt bits by DEBT-OFFSET — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:91` -> `mask-pos`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: `amount` relative to the current collateral row (the removing-all branch)
- Exploit idea: `mask-pos` maps an asset id to a bit position, offsetting debt bits by DEBT-OFFSET. Reach it through `collateral-remove` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove` with `amount` relative to the current collateral row (the removing-all branch), then read `mask-pos` state before and after in the same block and assert the two sides of the invariant are equal.
