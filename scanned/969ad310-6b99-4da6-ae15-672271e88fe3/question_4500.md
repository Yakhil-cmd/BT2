# Q4500: unpack-u16 via liquidate-multi: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the trait principals supplied per entry reach `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it unpacks eight u16 curve fields from one packed word, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `liquidate-multi` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the trait principals supplied per entry across its boundary values through `liquidate-multi` in simnet and assert `unpack-u16` never returns a value that breaks the invariant.
