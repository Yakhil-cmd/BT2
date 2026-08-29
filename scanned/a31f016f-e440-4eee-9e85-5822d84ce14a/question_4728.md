# Q4728: mask-update via liquidate-multi: prime shared state so the next caller in the block is eval

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the trait principals supplied per entry reach `mask-update` (mainnet/contracts/market/v0-market-vault.clar:94) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it sets or clears one bit, clearing only when the row reaches exactly zero, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:94` -> `mask-update`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `mask-update` sets or clears one bit, clearing only when the row reaches exactly zero. Reach it through `liquidate-multi` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz the trait principals supplied per entry across its boundary values through `liquidate-multi` in simnet and assert `mask-update` never returns a value that breaks the invariant.
