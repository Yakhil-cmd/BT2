# Q1881: interest-rate via redeem: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797), controlling `min-out`, drive `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) — which interpolates the packed curve at the current utilization — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment, and cause permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `min-out`
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `interest-rate` touches, run `redeem` with `min-out`, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
