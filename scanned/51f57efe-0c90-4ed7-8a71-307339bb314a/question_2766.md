# Q2766: receive-underlying via redeem: seize from a position that is solvent under the mask its o

## Question
Entering through `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) while controlling `recipient`, can an unprivileged attacker make `receive-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:291) seize from a position that is solvent under the mask its own operations were validated against? `receive-underlying` pulls the underlying from a named account, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:291` -> `receive-underlying`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `recipient`
- Exploit idea: `receive-underlying` pulls the underlying from a named account. Reach it through `redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `recipient` across its boundary values through `redeem` in simnet and assert `receive-underlying` never returns a value that breaks the invariant.
