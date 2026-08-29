# Q3528: calc-index-next via repay: prime shared state so the next caller in the block is eval

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls the `ft` trait principal reach `calc-index-next` (mainnet/contracts/vault/v0-vault-stx.clar:183) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it applies a multiplier to the current index, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:183` -> `calc-index-next`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `calc-index-next` applies a multiplier to the current index. Reach it through `repay` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the `ft` trait principal across its boundary values through `repay` in simnet and assert `calc-index-next` never returns a value that breaks the invariant.
