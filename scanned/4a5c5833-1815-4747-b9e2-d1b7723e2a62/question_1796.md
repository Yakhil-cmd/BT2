# Q1796: unpack-u16 via accrue: make a victim's position resolve to a worse efficiency gro

## Question
Does `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) let an unprivileged attacker who controls whether an earlier call in the same block already advanced last-update reach `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it unpacks eight u16 curve fields from one packed word, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: whether an earlier call in the same block already advanced last-update
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `accrue` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `accrue` twice with whether an earlier call in the same block already advanced last-update varied, and assert that the value `unpack-u16` returns is identical in both runs; a divergence confirms the finding.
