# Q3272: vault-accrue via repay: make a victim's position resolve to a worse efficiency gro

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls the `ft` trait principal reach `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it dispatches accrual to one of six vaults by asset id, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `repay` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `repay` twice with the `ft` trait principal varied, and assert that the value `vault-accrue` returns is identical in both runs; a divergence confirms the finding.
