# Q3824: relevant via repay: reprice every other holder's collateral in the same transa

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls the `ft` trait principal reach `relevant` (mainnet/contracts/market/v0-market-vault.clar:175) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it drops any position row whose bit is not present in the enabled mask, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:175` -> `relevant`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `relevant` drops any position row whose bit is not present in the enabled mask. Reach it through `repay` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `repay` twice with the `ft` trait principal varied, and assert that the value `relevant` returns is identical in both runs; a divergence confirms the finding.
