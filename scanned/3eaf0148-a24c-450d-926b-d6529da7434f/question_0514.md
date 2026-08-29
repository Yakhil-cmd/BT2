# Q0514: next-index via repay: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `repay` (mainnet/contracts/market/v0-4-market.clar:1316) while controlling `on-behalf-of`, naming any third-party principal, can an unprivileged attacker make `next-index` (mainnet/contracts/vault/v0-vault-stx.clar:379) write a stranger's ledger through an unsolicited on-behalf-of call? `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting, so the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block would fail, yielding direct theft of user funds at rest or in motion.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:379` -> `next-index`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `on-behalf-of`, naming any third-party principal
- Exploit idea: `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting. Reach it through `repay` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: Set up the position in simnet, call `repay` with `on-behalf-of`, naming any third-party principal, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
