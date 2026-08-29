# Q3324: send-underlying via redeem: route a victim's mandatory payout through a principal that

## Question
Does `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) let an unprivileged attacker who controls `min-out` reach `send-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:296) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it pushes the underlying under an `as-contract?` post-condition scope, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:296` -> `send-underlying`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `min-out`
- Exploit idea: `send-underlying` pushes the underlying under an `as-contract?` post-condition scope. Reach it through `redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `min-out` across its boundary values through `redeem` in simnet and assert `send-underlying` never returns a value that breaks the invariant.
