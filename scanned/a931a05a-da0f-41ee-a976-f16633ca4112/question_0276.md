# Q0276: increment via collateral-remove-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls `amount` used for BOTH the collateral removal and the share redemption reach `increment` (mainnet/contracts/market/v0-market-vault.clar:137) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it advances the user-id nonce, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:137` -> `increment`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `amount` used for BOTH the collateral removal and the share redemption
- Exploit idea: `increment` advances the user-id nonce. Reach it through `collateral-remove-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `amount` used for BOTH the collateral removal and the share redemption across its boundary values through `collateral-remove-redeem` in simnet and assert `increment` never returns a value that breaks the invariant.
