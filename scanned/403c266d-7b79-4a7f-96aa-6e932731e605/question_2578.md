# Q2578: total-assets via accrue: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) while controlling whether an earlier call in the same block already advanced last-update, can an unprivileged attacker make `total-assets` (mainnet/contracts/vault/v0-vault-stx.clar:334) write a stranger's ledger through an unsolicited on-behalf-of call? `total-assets` adds `(- debt borrowed)` as accrued interest that no token in the vault yet backs, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:334` -> `total-assets`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: whether an earlier call in the same block already advanced last-update
- Exploit idea: `total-assets` adds `(- debt borrowed)` as accrued interest that no token in the vault yet backs. Reach it through `accrue` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `accrue` with whether an earlier call in the same block already advanced last-update, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
