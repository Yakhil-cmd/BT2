# Q5400: calc-utilization via deposit: seize from a position that is solvent under the mask its o

## Question
Does `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763) let an unprivileged attacker who controls whether the vault is at a zero-supply or zero-asset edge reach `calc-utilization` (mainnet/contracts/vault/v0-vault-stx.clar:164) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it divides debt by available liquidity, which can exceed BPS when debt outruns assets, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:164` -> `calc-utilization`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: whether the vault is at a zero-supply or zero-asset edge
- Exploit idea: `calc-utilization` divides debt by available liquidity, which can exceed BPS when debt outruns assets. Reach it through `deposit` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz whether the vault is at a zero-supply or zero-asset edge across its boundary values through `deposit` in simnet and assert `calc-utilization` never returns a value that breaks the invariant.
