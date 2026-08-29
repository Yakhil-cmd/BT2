# Q3799: receive-tokens via repay: write a stranger's ledger through an unsolicited on-behalf

## Question
`receive-tokens` (mainnet/contracts/market/v0-market-vault.clar:256) pulls an asset from a named account. Can an unprivileged caller of `repay` (mainnet/contracts/market/v0-4-market.clar:1316), by choosing `on-behalf-of`, naming any third-party principal, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:256` -> `receive-tokens`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `on-behalf-of`, naming any third-party principal
- Exploit idea: `receive-tokens` pulls an asset from a named account. Reach it through `repay` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `repay` with `on-behalf-of`, naming any third-party principal, then read `receive-tokens` state before and after in the same block and assert the two sides of the invariant are equal.
