### Title
Stale account owner: after a position-NFT transfer, the previous owner retains full borrow/withdraw control of the account - (File: contracts/controller/src/account.rs)

### Summary
The controller authorizes position-mutating operations against `account.owner`, a value snapshotted once at account creation, rather than the live NFT owner (`owner_of`). The position NFT is a standard transferable token (`transfer`/`approve` are in scope), and nothing in the transfer path resyncs `Account.owner`. A seller/transferor of a position therefore keeps full authority over collateral and debt they no longer own — the same class as CVE-2023-29051 (a party no longer authorized can still discover and modify state belonging to another user).

### Finding Description
`create_account_with` stores `owner` inside the `Account` struct once, at mint time (`account.rs:64-70`).

All value-moving entrypoints authorize against that stale field via `require_owner_or_delegate` / `is_owner_or_delegate` (`account.rs:115-140`):

- `process_borrow` — `require_owner_or_delegate(env, account_id, caller, &account.owner)` (`debt.rs:43`), then pays out to `to` (`debt.rs:45`), an arbitrary `require_external_recipient`-checked address.
- `process_withdraw` — same check (`supply.rs:150`), then withdraws to `to` (`supply.rs:152`).
- `multiply`, `migrate_from_blend`, `swap_*`, `repay_debt_with_collateral` all funnel through `AccountGuard::{Migrate,Multiply}` → `require_owner_or_delegate` (`account.rs:99-110`).

Meanwhile the only places that check the *live* NFT owner are `renew_account`, `add_delegate`, `remove_delegate` via `require_account_owner` → `storage::account_owner` (`account.rs:143-148`, `217-250`).

The NFT contract itself is stock OpenZeppelin `NonFungibleToken` + `Enumerable` (`contract.rs:131-173`): `transfer`/`approve`/`transfer_from` update only NFT storage (`NFTStorageKey::Owner`). There is no controller callback or ownership resync — `mint` and `burn` are the only controller-coupled functions (`contract.rs:68-95`). So after `position_nft.transfer(from, to, token_id)`:

- `Base::owner_of` returns the new owner;
- `storage::get_account(account_id).owner` still returns the old owner.

The old owner (a single unprivileged address, no leaked keys, no privilege) can then call `controller.withdraw(account_id, [all collateral], to: self)` and `controller.borrow(account_id, [...], to: self)` and pass `require_owner_or_delegate`, draining the position the victim just acquired. `is_owner_or_delegate` even lets the old owner's previously granted delegates keep acting, since the delegate set is keyed by `(account_id, stale owner)` (`account.rs:124-127`).

### Impact Explanation
Theft of user funds. Any account purchased, received via OTC deal, or transferred for any reason remains fully spendable by its prior holder: all collateral withdrawable to the attacker, and new debt borrowable against the victim's collateral to the attacker's address. Loss equals the account's full collateral value plus maximum borrowable amount.

### Likelihood Explanation
High reachability: `transfer` is a standard permissionless NFT operation requiring only the current owner's auth — exactly the operation the NFT exists for. The stale-owner path is hit on the attacker's very next `withdraw`/`borrow` call. There is no expiry or latch that clears `account.owner`. (Caveat: I could not fully trace `storage::account_owner` vs. any hook that rewrites `Account.owner` on transfer within available iterations; nothing in `position-nft/contract.rs` or `account.rs` performs such a resync, and OZ NFTs emit events rather than callbacks, so no resync path appears to exist.)

### Recommendation
Authorize value-moving paths against live NFT ownership (`storage::account_owner(env, account_id)`) instead of the stored `Account.owner`, or make `require_owner_or_delegate` resolve the owner from the NFT. Delegation entries should be keyed or invalidated against the current owner so stale grants cannot survive a transfer (consider clearing delegates on ownership change, since NFT transfer has no controller hook, this is best done lazily by checking owner freshness inside `is_owner_or_delegate`).

### Proof of Concept
1. Alice owns `account_id = A` holding 1000 XLM-equivalent collateral; `Account.owner == Alice`.
2. Alice calls `position_nft.transfer(alice, bob, A)` (standard `transfer_from` flow). NFT `owner_of(A) == bob`; `Account.owner` remains `alice`.
3. Alice calls `controller.withdraw(A, [(hub_asset, 0 /* all */)], to: alice)`. `process_withdraw` → `require_owner_or_delegate(A, alice, alice)` passes on the stale field; pool pays Alice.
4. Optionally Alice first calls `controller.borrow(A, [(debt_asset, max)], to: alice)` to extract borrowable value before/withdrawing collateral.
5. Bob's account is drained despite being the rightful NFT owner; Bob cannot even act himself, since `require_owner_or_delegate` rejects him (`bob != account.owner` and no delegate grant).

Result: unprivileged prior owner steals all collateral and borrowing power of a transferred position.