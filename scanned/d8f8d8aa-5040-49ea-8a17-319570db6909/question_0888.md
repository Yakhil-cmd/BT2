# Q0888: get-available-assets via accrue: push a third party's position past a fold bound so every e

## Question
Does `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) let an unprivileged attacker who controls whether an earlier call in the same block already advanced last-update reach `get-available-assets` (mainnet/contracts/vault/v0-vault-stx.clar:481) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it reads real liquidity, a different quantity from the `assets` var that `redeem` also gates on, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:481` -> `get-available-assets`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: whether an earlier call in the same block already advanced last-update
- Exploit idea: `get-available-assets` reads real liquidity, a different quantity from the `assets` var that `redeem` also gates on. Reach it through `accrue` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz whether an earlier call in the same block already advanced last-update across its boundary values through `accrue` in simnet and assert `get-available-assets` never returns a value that breaks the invariant.
