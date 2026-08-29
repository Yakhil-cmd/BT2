# Q5744: oracle-price-legal via collateral-add: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls the `ft` trait principal reach `oracle-price-legal` (mainnet/contracts/market/v0-4-market.clar:362) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it accepts any price strictly greater than zero, with no upper bound and no sanity band, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:362` -> `oracle-price-legal`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `oracle-price-legal` accepts any price strictly greater than zero, with no upper bound and no sanity band. Reach it through `collateral-add` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `collateral-add` twice with the `ft` trait principal varied, and assert that the value `oracle-price-legal` returns is identical in both runs; a divergence confirms the finding.
