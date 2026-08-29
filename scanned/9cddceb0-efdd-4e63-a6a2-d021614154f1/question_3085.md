# Q3085: create via liquidate-multi: write a stranger's ledger through an unsolicited on-behalf

## Question
Can an unprivileged attacker entering through `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593), controlling the trait principals supplied per entry, drive `create` (mainnet/contracts/market/v0-market-vault.clar:150) — which binds a principal to a fresh numeric id — to write a stranger's ledger through an unsolicited on-behalf-of call, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:150` -> `create`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `create` binds a principal to a fresh numeric id. Reach it through `liquidate-multi` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate-multi` with the trait principals supplied per entry, then read `create` state before and after in the same block and assert the two sides of the invariant are equal.
