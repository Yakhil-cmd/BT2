# Q1688: socialize-debt via borrow: prime shared state so the next caller in the block is eval

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the `ft` trait principal reach `socialize-debt` (mainnet/contracts/vault/v0-vault-stx.clar:944) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it writes down `lindex` by one ratio while reducing `assets` by a completely different `principal-reduction`, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:944` -> `socialize-debt`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `socialize-debt` writes down `lindex` by one ratio while reducing `assets` by a completely different `principal-reduction`. Reach it through `borrow` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with the `ft` trait principal varied, and assert that the value `socialize-debt` returns is identical in both runs; a divergence confirms the finding.
