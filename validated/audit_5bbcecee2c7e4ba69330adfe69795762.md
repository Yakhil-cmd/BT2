### Title
Stale `account.owner` lets a previous NFT holder retain spending authority over a transferred account - (File: contracts/controller/src/account.rs)

### Summary
The controller records the account owner in the `Account` struct at creation time (`create_account_with` sets `account.owner = owner`), and all spending-authority checks in `require_owner_or_delegate`/`is_owner_or_delegate` compare `caller` against that stored snapshot. Separately, `require_account_owner` resolves the *current* owner through `storage::account_owner`, i.e. live position-NFT ownership. Because `withdraw`, `borrow`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and `migrate_from_blend` all authorize against the stored `account.owner` rather than the live NFT owner, transferring the position NFT does not revoke the previous owner's authority — the ex-owner can still impersonate "the account owner" and act on the account.

### Finding Description
Analog of CVE-2023-25559: identity is inferred from a channel that no longer reflects the real principal. In DataHub it was a smuggled `X-DataHub-Actor` header; here it is the stale `owner` field persisted in `Account`.

- `create_account_with` stores `owner` inside `Account` at mint time and never updates it (contracts/controller/src/account.rs:64-70).
- `is_owner_or_delegate` returns `true` when `caller == owner` where `owner` is `account.owner`, and resolves delegates under that same stale key via `storage::get_delegates(env, account_id, owner)` (account.rs:115-127).
- `process_withdraw` loads the account and calls `require_owner_or_delegate(env, account_id, caller, &account.owner)` before paying out collateral (contracts/controller/src/positions/supply.rs:149-157); `process_borrow` does the same before drawing debt (contracts/controller/src/positions/debt.rs:42-57).
- In contrast, `require_account_owner` deliberately reads `storage::account_owner(env, account_id)` — live NFT ownership — for `add_delegate`/`remove_delegate`/`renew_account` (account.rs:143-148), confirming the codebase treats NFT ownership as canonical for identity.
- `position-nft::transfer` moves the token but there is no hook updating `account.owner` or the delegate list, which is keyed under the old owner address.

Consequence: after the NFT is transferred (sold, moved to a contract, used as collateral elsewhere), `storage::account_owner` changes but `account.owner` and the delegate set do not. The previous owner — and any delegate they granted while owning the account — still satisfy `require_owner_or_delegate` on every mutating entrypoint.

### Impact Explanation
An unprivileged previous owner can call `withdraw(account_id, withdrawals, to)` or `borrow(account_id, borrows, to)` on an account they no longer own, directing proceeds to `to: Some(their_address)` (`require_external_recipient` only screens protocol-internal addresses). They can drain all withdrawable collateral down to the solvency floor, or borrow up to the account's cached LTV against the new owner's collateral and walk away — direct theft of user funds. Delegates granted by the old owner retain identical reach. The new NFT owner is also partially locked out of owner-gated paths until the stored owner is refreshed.

### Likelihood Explanation
Position NFTs are designed to be transferable (position-nft exposes `transfer`/`approve`), so ownership change is a normal, expected event. The attacker needs only to have owned the account previously — no privileged role, no oracle manipulation. Every withdrawal/borrow path reaches `require_owner_or_delegate` with the stale field.

### Recommendation
Resolve the owner from `storage::account_owner(account_id)` (the live NFT owner) inside `is_owner_or_delegate`/`require_owner_or_delegate` instead of trusting `account.owner`, or update `account.owner` and migrate/clear the delegate list in a controller-side hook whenever the NFT is transferred (e.g., have position-nft `transfer`/`burn` notify the controller). Keying delegates off the live owner — as `require_account_owner` already does — makes the two identity channels consistent.

### Proof of Concept
1. Alice supplies collateral via `supply(account_id = 0, spoke_id, assets)`; an account is created with `account.owner = alice`.
2. Alice calls `position_nft.transfer(alice, bob, token_id)` (or sells it on a marketplace). `storage::account_owner` now returns Bob; `account.owner` still equals Alice.
3. Alice calls `withdraw(account_id, [hub_payment(amount, collateral_asset)], to = alice)`.
4. `require_authorized_caller` passes (Alice signs). `require_owner_or_delegate` compares `caller == account.owner` → `alice == alice` → passes, even though Bob is the current owner.
5. `settle_withdraw` pays the pool's collateral to Alice; Bob's NFT now backs a drained account.

Alternatively, a delegate `d` that Alice approved before the transfer calls `borrow(account_id, borrows, to = d)`: `is_owner_or_delegate` finds `d` in `get_delegates(account_id, alice)` with `is_active`, and debt is minted against Bob's collateral.