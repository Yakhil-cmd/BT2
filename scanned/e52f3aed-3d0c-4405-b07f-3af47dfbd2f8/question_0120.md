# Q0120: unpack-u16 via collateral-add: make a victim's position resolve to a worse efficiency gro

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls call ordering within the block reach `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it unpacks eight u16 curve fields from one packed word, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: call ordering within the block
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `collateral-add` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz call ordering within the block across its boundary values through `collateral-add` in simnet and assert `unpack-u16` never returns a value that breaks the invariant.
