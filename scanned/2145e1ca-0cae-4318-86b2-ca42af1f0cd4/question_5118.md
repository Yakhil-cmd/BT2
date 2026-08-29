# Q5118: next-index via accrue: reprice every other holder's collateral in the same transa

## Question
Entering through `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) while controlling the utilization the rate is interpolated at, can an unprivileged attacker make `next-index` (mainnet/contracts/vault/v0-vault-stx.clar:379) reprice every other holder's collateral in the same transaction that profits from it? `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:379` -> `next-index`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: the utilization the rate is interpolated at
- Exploit idea: `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting. Reach it through `accrue` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz the utilization the rate is interpolated at across its boundary values through `accrue` in simnet and assert `next-index` never returns a value that breaks the invariant.
