# Q3735: insert via repay: seize from a position that is solvent under the mask its o

## Question
`insert` (mainnet/contracts/market/v0-market-vault.clar:159) rewrites the whole registry entry for a user id. Can an unprivileged caller of `repay` (mainnet/contracts/market/v0-4-market.clar:1316), by choosing `on-behalf-of`, naming any third-party principal, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:159` -> `insert`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `on-behalf-of`, naming any third-party principal
- Exploit idea: `insert` rewrites the whole registry entry for a user id. Reach it through `repay` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `insert` touches, run `repay` with `on-behalf-of`, naming any third-party principal, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
