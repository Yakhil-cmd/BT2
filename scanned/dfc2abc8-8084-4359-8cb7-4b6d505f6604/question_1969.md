# Q1969: resolve-pyth via call-ststx-ratio: write a stranger's ledger through an unsolicited on-behalf

## Question
Can an unprivileged attacker entering through `call-ststx-ratio` (mainnet/contracts/market/v0-4-market.clar:1015), controlling the block and transaction position at which the external ratio is fetched, drive `resolve-pyth` (mainnet/contracts/market/v0-4-market.clar:312) — which reads the Pyth storage record for a 32-byte ident — to write a stranger's ledger through an unsolicited on-behalf-of call, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:312` -> `resolve-pyth`
- Entrypoint: `call-ststx-ratio` (`mainnet/contracts/market/v0-4-market.clar:1015`), unprivileged and publicly callable
- Attacker controls: the block and transaction position at which the external ratio is fetched
- Exploit idea: `resolve-pyth` reads the Pyth storage record for a 32-byte ident. Reach it through `call-ststx-ratio` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `call-ststx-ratio` with the block and transaction position at which the external ratio is fetched, then read `resolve-pyth` state before and after in the same block and assert the two sides of the invariant are equal.
