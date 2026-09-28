### Title
Stale `account.owner` field grants account authority to the previous NFT holder after position transfer - (File: contracts/controller/src/account.rs)

### Summary
The controller maintains two sources of truth for account ownership: the `owner` field stored inside the `Account` struct (written once at `create_account`, account.rs:65) and the position-nft's live `owner_of` (read by `storage::account_owner`). `require_owner_or_delegate` — the gate used by `borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and `migrate_from_blend` — authenticates `caller` against `account.owner` (account.rs:102, 106, 121), while `require_account_owner` (delegate grants, `renew_account`) authenticates against the NFT owner (account.rs:143-148). After `position-nft::transfer`/`transfer_from` moves the NFT, `account.owner` still names the seller, so the seller retains full owner-or-delegate authority over an account it no longer owns — the same class as CVE-2015-7224: an authority check satisfied by a credential that was implicitly broadened/detached from the real identity.

### Finding Description
- `create_account` stores `owner` inside the `Account` struct at mint time (account.rs:64-70). Nothing in `positions/supply.rs`, `positions/debt.rs`, or the strategy files rewrites that field — it is set once and never resynced (verified by grepping `account.owner` writes across `contracts/controller/src`).
- `load_or_create_account` calls `require_owner_or_delegate(env, account_id, caller, &account.owner)` for the `Migrate` and `Multiply` guards (account.rs:101-109), and `is_owner_or_delegate` returns `true` whenever `caller == owner` (account.rs:121-123).
- `require_account_owner`, by contrast, loads `storage::account_owner(env, account_id)` — the NFT owner — and rejects `caller` if it differs (account.rs:143-148).
- The declared model in `scripts/permissionless_entrypoints.txt` states that NFT transfer makes the previous owner's delegate grants "go inactive" and that only the holder can move the account — i.e., authority is intended to follow the NFT. `is_owner_or_delegate` instead follows the stale struct field.

### Impact Explanation
After a victim sells or transfers their position NFT (or has it moved via a legitimately granted `transfer_from` approval), the previous holder can still call `borrow`, `withdraw`, `swap_collateral`, `repay_debt_with_collateral`, `multiply`, `flash_position`, and `migrate_from_blend` against `account_id` because `is_owner_or_delegate` matches `caller` to the stale `account.owner`. The ex-owner can drain the account's collateral via `withdraw`/`borrow` up to the risk gates, grief the new owner via forced leverage or collateral swaps, or sandwich the transfer. This is theft of user funds reachable by a single unprivileged address. Uncertainty: I could not confirm whether some sync path rewrites `Account.owner` on NFT transfer (no such write was found in controller sources; the position-nft contract has no callback into the controller), so if an undocumented resync exists elsewhere the finding downgrades to a design inconsistency.

### Likelihood Explanation
High if the stale field stands: NFT transfers are a supported user action (`position-nft::transfer`, `transfer_from` are declared entrypoints), and every account a user buys/sells secondhand carries the latent authority of the previous holder. Exploitation requires only that the ex-owner retained or regained a signing key — no privileged role, no flash loan, no oracle manipulation.

### Recommendation
Delete the `owner` field from `Account` (or stop trusting it): make `is_owner_or_delegate`/`require_owner_or_delegate` resolve ownership through `storage::account_owner` (the NFT) exactly as `require_account_owner` already does, and key the delegate map off the live NFT owner. Add a test asserting that after `transfer_from`, the previous owner's `borrow`/`withdraw`/`multiply` calls revert with `NotAuthorized`.

### Proof of Concept
1. Alice supplies collateral and borrows, holding `account_id = A` whose `Account.owner == ALICE`.
2. Alice calls `position-nft::transfer` to Bob (or an approved operator calls `transfer_from` to Bob). NFT `owner_of(A)` is now Bob; `Account.owner` remains `ALICE`.
3. Alice calls `controller::borrow(caller=ALICE, account_id=A, hub_asset, amount)`. `load_or_create_account` → `require_owner_or_delegate` → `is_owner_or_delegate` returns true at account.rs:121 because `caller == account.owner` (stale). `caller.require_auth()` passes — Alice signs.
4. Borrowed funds are drawn against account `A`'s collateral, harming Bob, the NFT owner. Optionally Alice then `withdraw`s remaining collateral within the health-factor gates.