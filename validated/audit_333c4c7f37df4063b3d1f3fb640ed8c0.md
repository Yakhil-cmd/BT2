### Title
Spending authority follows the stale stored `Account.owner`, not the NFT holder — a transferred position remains spendable by the previous owner - ([File: contracts/controller/src/account.rs])

### Summary
The bug class is a scope/ownership boundary enforced on one route family but bypassed on a sibling "self" family. In XOXNO Lending the canonical ownership record is the position NFT (`owner_of(token_id)` is documented as the account owner in `contracts/position-nft/src/contract.rs:2`), and NFT `transfer`/`approve` are stock OpenZeppelin operations reachable by any token holder. However, every fund-moving controller path (`borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`) authorizes through `require_owner_or_delegate`, which compares the caller against `account.owner` — a field written once at mint in `create_account_with` (`account.rs:65`) and never updated on NFT transfer. The result mirrors the Gitea report exactly: the canonical ownership surface (NFT ownership; `require_account_owner` via `storage::account_owner` for `renew_account`/`add_delegate`/`remove_delegate`) tracks the current holder, while the spending route family keeps honoring the stale stored owner.

### Finding Description
- `create_account_with` sets `Account { owner: owner.clone(), .. }` at mint time only (`contracts/controller/src/account.rs:64-70`). No controller code path rewrites `account.owner`; the NFT contract's `transfer`/`approve` (stock OZ enumerable) have no callback into the controller.
- `is_owner_or_delegate` returns `true` whenever `caller == owner`, where `owner` is `&account.owner` — the stale stored field (`account.rs:121`). It then checks the delegate list keyed under that same stored owner (`account.rs:126`).
- `load_or_create_account` applies `require_owner_or_delegate` for `Migrate` and `Multiply` guards (`account.rs:101-109`), and the same guard is reached by `positions/debt.rs`, `positions/supply.rs`, `strategies/swap_debt.rs`, `swap_collateral.rs`, `repay_debt_with_collateral.rs`, `multiply.rs`, `flash_position.rs`, `migrate_blend.rs` per the `require_auth`/guard usage confirmed across those files and declared in `scripts/permissionless_entrypoints.txt:49-56`.
- The split is visible inside `account.rs` itself: `require_account_owner` (used by `renew_account`, `add_delegate`, `remove_delegate`, `account.rs:143-148, 221, 250`) resolves ownership via `storage::account_owner(env, account_id)`, a separate source from `account.owner`. So the protocol already maintains two notions of "owner," and only the non-spending routes use the live one.

### Impact Explanation
After Alice transfers her position NFT to Bob (a supported, in-scope action), the stored `Account.owner` remains Alice. Alice — or any delegate she previously registered — retains full spending authority: `withdraw` drains the account's collateral to Alice, and `borrow` draws debt against collateral Bob now believes he owns. This is direct theft of user funds by an unprivileged address: the attacker needs only to acquire a position NFT (purchase, or transfer-and-front-run) and the seller retains secret residual authority. Symmetrically, Bob cannot revoke Alice's pre-transfer delegates, since they are keyed under Alice as stored owner (`account.rs:126`).

### Likelihood Explanation
Requires only a standard NFT transfer — an explicitly in-scope, unprivileged action (`position-nft transfer/approve`). No privileged role, no oracle manipulation, no race. Any OTC sale or wallet migration of a position creates the condition automatically.

### Recommendation
Make the NFT the single source of truth for spending authority: in `is_owner_or_delegate`/`require_owner_or_delegate`, resolve the owner via `storage::account_owner`/`owner_of` rather than the cached `account.owner` field (or update `account.owner` through a controller-mediated transfer hook and remove raw NFT transfer). Re-key delegate storage to the account id rather than the owner address, and add a regression test that transfers a position NFT and asserts the prior owner can no longer `withdraw`/`borrow`.

### Proof of Concept
1. Alice `supply`s USDC creating `account_id = A`; `Account.owner = alice`, NFT `owner_of(A) = alice`.
2. Alice calls `position_nft.transfer(alice, bob, A)`. `owner_of(A) = bob`; `Account.owner` still `alice` (`account.rs:64-70` — no update path exists).
3. Alice calls `controller.withdraw(caller=alice, account_id=A, hub_asset=USDC, amount=i128::MAX)`. `load_or_create_account`/spend-path guard runs `require_owner_or_delegate(env, A, alice, &account.owner)`; `alice == account.owner` (`account.rs:121`) passes. Collateral is paid out to the previous owner while Bob holds the NFT.
4. Variant: Alice's pre-transfer delegate (an active position manager) retains authority for the same reason (`account.rs:124-126`), and Bob cannot remove it because his delegate operations key under `bob`.

Uncertainty noted: `storage::account_owner` (in `contracts/controller/src/storage/account.rs`) was not read in full; if it also returns the stale stored field rather than `owner_of`, the inconsistency between route families narrows but the core flaw — spend authority pinned to a mint-time owner field that NFT transfers never update — is unchanged.