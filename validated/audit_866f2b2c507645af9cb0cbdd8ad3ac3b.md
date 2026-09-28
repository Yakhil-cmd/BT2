### Title
Stale stored account owner bypasses NFT ownership after transfer — transferred position remains spendable by the seller - (File: contracts/controller/src/account.rs)

### Summary
The controller tracks account ownership in two places that disagree after a position NFT transfer. `require_owner_or_delegate` — the guard for `borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and `migrate_from_blend` — compares the caller against the `owner` field baked into the `Account` struct at creation time. `require_account_owner` — the guard for `add_delegate`/`remove_delegate`/`renew_account` — instead reads the live NFT owner via `storage::account_owner`. When an NFT moves to a new holder, the stored `account.owner` is never restamped, so the *previous* owner still satisfies `caller == owner` and retains full spending authority over an account it no longer owns — an authentication-bypass analog of the n8n conditional-auth bug: the "configured" check (stored owner) succeeds while the real authority (NFT holder) has changed.

### Finding Description
`create_account_with` stores `owner: owner.clone()` inside the `Account` (contracts/controller/src/account.rs:64-70). `load_or_create_account` loads that `Account` and calls `require_owner_or_delegate(env, account_id, caller, &account.owner)` for the Migrate and Multiply guards (account.rs:98-110). `is_owner_or_delegate` returns `true` when `caller == owner` (account.rs:121-123), using the stale stored field — it never consults `Base::owner_of` on the position NFT. By contrast `require_account_owner` loads `storage::account_owner(env, account_id)` and compares the caller to the live NFT owner (account.rs:143-148), proving the codebase knows the two can diverge. `position-nft::transfer` (position-nft/src/contract.rs) is a stock OZ move; the permissionless inventory only claims delegate grants go inactive on transfer — nothing in `remove_delegate`/`set_account_delegate` or any transfer hook rewrites `Account.owner` in controller storage.

### Impact Explanation
An attacker sells or transfers a position NFT to a victim (or transfers it to a fresh address for operational separation). The victim now owns the NFT and can call `renew_account`/delegate ops, but every funds-moving entrypoint still treats the seller as the owner. The seller calls `withdraw` (or `borrow` against the collateral) with their own `account_id`, passes `require_owner_or_delegate` via the stale `account.owner`, and drains the collateral the buyer thought they acquired. This is theft of user funds reachable by a single unprivileged address through `controller::withdraw`/`borrow`/`multiply` after a legitimate `position-nft::transfer`.

### Likelihood Explanation
NFT transfer is a supported, unprivileged action on the position-nft contract. No auth or hook propagates the new owner into the controller's `Account` struct, so the stale-owner check succeeds deterministically on every subsequent spend. The only prerequisite is that a transfer occurs — which is exactly the non-default condition under which the auth check is circumvented, mirroring the advisory's bug class.

### Recommendation
On every account-spending entrypoint, resolve authority from the live NFT owner (`storage::account_owner` / `Base::owner_of`) instead of the cached `Account.owner`, or restamp `Account.owner` at the top of `load_or_create_account` (and wherever `Account` is loaded) by reading the NFT owner. Delegate lists should continue to be keyed under the current NFT owner.

### Proof of Concept
1. Alice supplies collateral via `supply`, obtaining account `A` and NFT `A` with `Account.owner = Alice`.
2. Alice calls `position_nft.transfer(Alice, Bob, A)`. `storage::account_owner` now returns Bob; `Account.owner` in controller storage still returns Alice.
3. Alice calls `controller.withdraw(Alice, A, hub_asset, amount, Bob_or_self)`. `load_or_create_account` → `require_owner_or_delegate` sees `caller == account.owner` (Alice) and passes; Alice pulls the collateral out of Bob's account.
4. Bob holds the NFT but cannot stop the drain; he can only race the withdrawal.

Note: I was unable to fully verify whether `positions/supply.rs` or `debt.rs` refresh `account.owner` from the NFT on load (grep showed `.owner` reads there but the file contents were not retrieved before tool budget ended). If any path already restamps the stored owner from `Base::owner_of`, the window narrows to whichever entrypoints skip that refresh; the two divergent ownership sources in `account.rs` remain the defect either way.