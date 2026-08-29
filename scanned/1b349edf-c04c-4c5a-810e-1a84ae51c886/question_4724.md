# Q4724: receive-underlying via redeem: make a victim's position resolve to a worse efficiency gro

## Question
Does `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797) let an unprivileged attacker who controls `recipient` reach `receive-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:291) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it pulls the underlying from a named account, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:291` -> `receive-underlying`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `recipient`
- Exploit idea: `receive-underlying` pulls the underlying from a named account. Reach it through `redeem` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `redeem` twice with `recipient` varied, and assert that the value `receive-underlying` returns is identical in both runs; a divergence confirms the finding.
