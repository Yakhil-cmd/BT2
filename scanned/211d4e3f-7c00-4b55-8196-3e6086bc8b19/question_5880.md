# Q5880: calc-utilization via redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) let an unprivileged attacker who controls `amount` of shares burned reach `calc-utilization` (mainnet/contracts/vault/v0-vault-stx.clar:164) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it divides debt by available liquidity, which can exceed BPS when debt outruns assets, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:164` -> `calc-utilization`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `amount` of shares burned
- Exploit idea: `calc-utilization` divides debt by available liquidity, which can exceed BPS when debt outruns assets. Reach it through `redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `amount` of shares burned across its boundary values through `redeem` in simnet and assert `calc-utilization` never returns a value that breaks the invariant.
