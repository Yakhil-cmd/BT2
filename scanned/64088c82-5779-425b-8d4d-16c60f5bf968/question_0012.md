# Q0012: convert-to-scaled-debt via collateral-remove: prime shared state so the next caller in the block is eval

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls the set of assets held reach `convert-to-scaled-debt` (mainnet/contracts/market/v0-4-market.clar:648) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it scales a token amount by the cached borrow index, rounding up on the borrow path, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:648` -> `convert-to-scaled-debt`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the set of assets held
- Exploit idea: `convert-to-scaled-debt` scales a token amount by the cached borrow index, rounding up on the borrow path. Reach it through `collateral-remove` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz the set of assets held across its boundary values through `collateral-remove` in simnet and assert `convert-to-scaled-debt` never returns a value that breaks the invariant.
