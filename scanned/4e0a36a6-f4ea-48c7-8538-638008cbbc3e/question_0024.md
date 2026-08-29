# Q0024: accrue-user-collateral via collateral-remove: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls the set of assets held reach `accrue-user-collateral` (mainnet/contracts/market/v0-4-market.clar:270) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it accrues only rows that `is-ztoken` recognises, skipping everything else, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:270` -> `accrue-user-collateral`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the set of assets held
- Exploit idea: `accrue-user-collateral` accrues only rows that `is-ztoken` recognises, skipping everything else. Reach it through `collateral-remove` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz the set of assets held across its boundary values through `collateral-remove` in simnet and assert `accrue-user-collateral` never returns a value that breaks the invariant.
