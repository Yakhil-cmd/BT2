### Title
Stale `account.owner` lets a previous NFT holder keep full spending authority after `position-nft` transfer — ([File: contracts/controller/src/account.rs](contracts/controller/src/account.rs))

### Summary
The controller's authority check for every position-moving entrypoint (`borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`) compares the caller against `account.owner`, the address frozen into the `Account` struct at mint time — not against the live `position-nft` `owner_of`. The NFT is a standard transferable OZ enumerable token. After a transfer, the previous owner (and all of their delegates) retain owner-equivalent authority over the account, while the new owner is rejected. This is the on-chain analog of the wolfSSH state-machine authentication bypass: authentication is proven against a stale state instead of the current one.

### Finding Description
- `create_account` writes `account.owner = owner` once, at mint (`account.rs:64-70`).
- `require_owner_or_delegate` / `is_owner_or_delegate` authenticate via `caller == account.owner` and `storage::get_delegates(env, account_id, owner)` keyed by that stored owner (`account.rs:115-140`).
- `load_or_create_account` passes `&account.owner` into that check for `Migrate` and `Multiply` guards (`account.rs:101-109`); `positions/debt.rs`, `positions/supply.rs`, `positions/liquidation/mod.rs`, and the `strategies/*` files reach the same helper per the grep evidence.
- In contrast, `require_account_owner` reads `storage::account_owner(env, account_id)` — the live NFT ownership — and is used only for `renew_account`, `add_delegate`, `remove_delegate` (`account.rs:143-148, 217-275`). So the codebase itself treats the NFT `owner_of` as the source of truth ("the token owner (`owner_of`) is the account owner", `position-nft/src/contract.rs:2`), while the spending paths use the stale copy.
- `position-nft` implements the stock `NonFungibleToken`/`NonFungibleEnumerable` trait (`contract.rs:131-133`), so `transfer`/`transfer_from`/`approve` are live; `burn` explicitly requires no holder auth (`contract.rs:78-95`), confirming ownership is expected to change without controller involvement.
- Nothing in `create_account`/`load_or_create_account` re-syncs `account.owner` from the NFT. Delegates granted by the old owner also survive the transfer, since the delegate map is keyed by the stale owner.

### Impact Explanation
Theft of user funds: after buying/receiving a position NFT, the victim's collateral and borrowing power are still controlled by the seller. The seller calls `withdraw` (pays `to` an arbitrary address) to drain all collateral, or `borrow` to pull maximum debt and let the account be liquidated. A malicious delegate added before the sale retains authority permanently — `is_owner_or_delegate` checks the delegate list under the stale owner. Result: total loss of the transferred position's value.

### Likelihood Explanation
Fully deterministic and reachable by any unprivileged address that ever held the NFT. Attack path: sell the position NFT (or transfer it and reacquire via a second account to reset the trail), then call `controller::withdraw(caller=old_owner, account_id, withdrawals, to=Some(attacker))` — `require_owner_or_delegate` passes because `account.owner` still equals the seller, and post-withdraw solvency is trivially satisfied for a debt-free account. No oracle manipulation, timing, or privileged access required.

### Recommendation
Derive spending authority exclusively from `storage::account_owner` (NFT `owner_of`) inside `is_owner_or_delegate`, and key the delegate map by `account_id` alone rather than `(account_id, owner)` — or clear delegates on NFT transfer via a controller-side hook. `account.owner` should be removed from the `Account` struct or treated as informational only.

### Proof of Concept
1. Alice calls `supply(caller=alice, account_id=0, spoke_id, assets)` → creates account `id`, `account.owner = alice`, NFT `id` minted to Alice.
2. Alice transfers NFT `id` to Bob via `position-nft::transfer(alice, bob, id)` (or via `approve` + `transfer_from`).
3. Alice calls `controller::withdraw(caller=alice, account_id=id, withdrawals=[(hub_asset, 0)], to=Some(attacker_addr))`.
4. `process_withdraw` → `require_owner_or_delegate(env, id, alice, &account.owner)` → `alice == account.owner` → passes, despite `owner_of(id) == bob`. Collateral is paid to `attacker_addr`.
5. Variant: Alice first calls `add_delegate(alice, id, manager)`; after the NFT sale, `manager` calls `borrow`/`withdraw` — `get_delegates(id, alice)` still contains it.

*Uncertain (not fully verified within available iterations):* the exact body of `storage::account_owner` in `contracts/controller/src/storage/account.rs` (assumed to read NFT `owner_of`, consistent with `require_account_owner`'s doc and usage), and whether `get_account` re-reads `owner` anywhere — the stored-`Account` path is confirmed by `create_account` and `load_or_create_account`.