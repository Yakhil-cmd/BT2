# Q3380: receive-underlying via transfer: route a victim's mandatory payout through a principal that

## Question
Does `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) let an unprivileged attacker who controls `amount` reach `receive-underlying` (mainnet/contracts/vault/v0-vault-stx.clar:291) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it pulls the underlying from a named account, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:291` -> `receive-underlying`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `receive-underlying` pulls the underlying from a named account. Reach it through `transfer` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `transfer` twice with `amount` varied, and assert that the value `receive-underlying` returns is identical in both runs; a divergence confirms the finding.
