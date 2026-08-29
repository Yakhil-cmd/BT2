# Q4712: mask-pos via liquidate-multi: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the trait principals supplied per entry reach `mask-pos` (mainnet/contracts/market/v0-market-vault.clar:91) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it maps an asset id to a bit position, offsetting debt bits by DEBT-OFFSET, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:91` -> `mask-pos`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `mask-pos` maps an asset id to a bit position, offsetting debt bits by DEBT-OFFSET. Reach it through `liquidate-multi` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with the trait principals supplied per entry varied, and assert that the value `mask-pos` returns is identical in both runs; a divergence confirms the finding.
