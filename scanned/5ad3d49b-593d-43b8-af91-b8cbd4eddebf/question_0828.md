# Q0828: user-safe-mask via collateral-add: seize from a position that is solvent under the mask its o

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls call ordering within the block reach `user-safe-mask` (mainnet/contracts/market/v0-4-market.clar:428) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it ANDs the user's collateral bits against the enabled bitmap but keeps ALL debt bits unfiltered, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:428` -> `user-safe-mask`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: call ordering within the block
- Exploit idea: `user-safe-mask` ANDs the user's collateral bits against the enabled bitmap but keeps ALL debt bits unfiltered. Reach it through `collateral-add` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz call ordering within the block across its boundary values through `collateral-add` in simnet and assert `user-safe-mask` never returns a value that breaks the invariant.
