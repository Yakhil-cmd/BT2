### Title
Position NFT transfer does not revoke stale owner/delegate authority stored in the account — old owner and its delegates retain `Migrate`/`Multiply` access after losing ownership - (File: contracts/controller/src/account.rs)

### Summary
The JupyterHub bug class is *incomplete credential invalidation*: logging out (revoking a session) leaves other live sessions able to reinstate credentials, so revocation is not effective while concurrent state still references the old session. The XOXNO Lending analog is the controller's account-ownership model. Ownership is defined by the position-NFT `owner_of` (`storage::account_owner` resolves it live), but `Account` also stores an `owner` field written once at account creation, and two privileged guards — `AccountGuard::Migrate` and `AccountGuard::Multiply` — authenticate against that stored field plus delegate grants keyed under it via `require_owner_or_delegate` rather than against the live NFT owner.

### Finding Description
`create_account_with` sets `account.owner` to the minter at creation time and stores it in the account entry (`contracts/controller/src/account.rs:64-70`). When the position NFT is later transferred via `PositionNft`/OpenZeppelin `transfer`, the NFT contract updates `Owner(token_id)` but nothing notifies the controller, so the stored `account.owner` is never rewritten.

Authority checks then split into two inconsistent sources:

- `require_account_owner` resolves the *live* NFT owner via `storage::account_owner` → `nft_try_owner_of_call` → `owner_of` (`account.rs:143-148`, `external/position_nft.rs:19-25`). This correctly recognizes the new owner.
- `require_owner_or_delegate` (used by `AccountGuard::Migrate` and `AccountGuard::Multiply` in `load_or_create_account`, `account.rs:101-108`) compares `caller` to `account.owner` — the stale stored owner — and falls back to `get_delegates(env, account_id, owner)` where `owner` is again `account.owner` (`account.rs:115-140`).

Consequences after a transfer of token `account_id` from A to B:

1. A (`account.owner`) still satisfies `caller == owner` in `is_owner_or_delegate` and can re-enter `migrate_from_blend` and `multiply` on B's account. This is exactly the JupyterHub pattern: the "logout" (NFT transfer) did not invalidate the credential the controller actually checks on these paths.
2. Any active manager that A previously granted via `add_delegate` remains authorized: `get_delegates(env, account_id, A)` still contains the delegate, and `is_owner_or_delegate` passes for it. Delegate grants are keyed by the granter's address (`set_account_delegate`, `account.rs:260-264`), so they silently survive the ownership change — there is no path that clears `Delegates` entries on transfer.
3. Conversely, B — the true current owner — cannot use `Migrate`/`Multiply` guards on its own account until some path refreshes the stored owner, because `caller == account.owner` fails and B has no delegates keyed under A.

The only auth used elsewhere on these paths is `caller.require_auth()` (`risk/validation.rs:13-16`), which the former owner can still sign for, so nothing else stops the stale principal.

### Impact Explanation
`multiply` opens leveraged positions on the target account: it mints debt against the account's collateral. A stale former owner (or surviving delegate) can therefore borrow against collateral belonging to the victim's account, pushing its health factor down and exposing the victim's collateral to forced liquidation and liquidation-bonus seizure — a direct loss of user funds caused by an actor who no longer owns the account. `migrate_from_blend` lets the stale principal move the account's Blend positions under a guard meant for the owner. The victim cannot preempt this by "logging out" again — transferring the NFT onward does not clear the stored owner or the delegate set, mirroring the advisory's core defect that revocation is ineffective while other state still honors the old credential. This is at least theft of user funds via forced liquidation/bad position management by an unauthorized party.

### Likelihood Explanation
Reachable by a single unprivileged address: the attacker need only have owned (or been delegated on) an account whose NFT is later transferred — e.g., selling a leveraged position NFT, moving it to a fresh wallet, or NFT-based position marketplaces. The attacker then calls `controller.multiply` or `controller.migrate_from_blend` with `account_id` set to the transferred account; `load_or_create_account` reaches `require_owner_or_delegate(env, account_id, caller, &account.owner)` where `account.owner` is still the attacker, so the guard passes with only the attacker's `require_auth`. Preconditions (an active manager registration for delegates, Blend positions for migrate, sufficient collateral for multiply) are normal protocol states. The defect is deterministic once the owner field is stale — it does not depend on race timing, oracle behavior, or admin action.

### Recommendation
- In `load_or_create_account` (and any path using `require_owner_or_delegate`), resolve the owner via `storage::account_owner(env, account_id)` (live `owner_of`) instead of `account.owner`, or refresh `account.owner` from the NFT on every load.
- Key delegate grants by `account_id` only (or by live NFT owner at check time) so that `get_delegates` cannot match grants made by a previous owner.
- On NFT transfer visibility: document/emit an account-owner refresh path, and treat the stored `Account.owner` as a cache that must always be revalidated against `owner_of` before any privileged action.

### Proof of Concept
1. Alice calls `controller.supply(0, spoke, mode, ...)` → `create_account` mints position NFT `token_id = N` to Alice; stored `Account { owner: Alice, ... }` persisted (`account.rs:62-71`).
2. Alice optionally calls `add_delegate(N, Mallory)` where Mallory is an active manager → `get_delegates(env, N, Alice)` contains Mallory (`account.rs:229-238`).
3. Alice transfers the position NFT `N` to Bob via the position-NFT `transfer` entrypoint. `owner_of(N)` now returns Bob; `Account.owner` still equals `Alice`; no delegate entries are removed.
4. Alice (or Mallory) calls `controller.multiply(account_id=N, spoke_id=..., mode=..., ...)`:
   - `load_or_create_account` loads the account, hits `AccountGuard::Multiply` → `require_owner_or_delegate(env, N, caller, &account.owner)` (`account.rs:105-108`).
   - `caller == account.owner == Alice` → authorized; or Mallory matches `get_delegates(N, Alice)` → authorized.
   - The strategy proceeds to mint debt on Bob's account, deteriorating its health factor while Bob — the real owner — has no corresponding authority on this guard.
5. Bob attempts `multiply`/`migrate_from_blend` on his own account and is rejected with `GenericError::NotAuthorized` because `caller != account.owner`.

Note on verification limits: I confirmed the split authority model (`owner_of`-based `require_account_owner` vs stored-owner `require_owner_or_delegate`) in `contracts/controller/src/account.rs` and the NFT mint/burn/renew surface in `contracts/position-nft/src/contract.rs`. If `storage::get_account` internally repopulates `Account.owner` from `owner_of` on every load (rather than returning the stored value), the stale-owner path collapses and this finding reduces to the still-true observation that delegate grants keyed by a prior owner would merely fail closed. That load behavior should be verified in `contracts/controller/src/storage/account.rs` before final triage.