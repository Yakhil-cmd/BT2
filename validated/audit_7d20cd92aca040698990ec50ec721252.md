### Title
Stale `account.owner` lets a previous NFT holder keep full control of a sold/transferred lending account — (File: contracts/controller/src/account.rs)

### Summary
Ownership of a lending account is meant to live in the position NFT: `owner_of(token_id)` is the account owner, and transferring the NFT is supposed to move control of the whole account (`contracts/position-nft/src/contract.rs:1-5`, `scripts/permissionless_entrypoints.txt:106-111`). However, every fund-moving controller path (`borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`) authorizes against `account.owner` — the address frozen into `Account` at creation in `create_account_with` (`account.rs:64-70`) — via `require_owner_or_delegate` (`account.rs:130-140`), which returns early when `caller == owner` (`account.rs:121-122`). Meanwhile `require_account_owner` (used by `add_delegate`, `remove_delegate`, `renew_account`) reads `storage::account_owner`, i.e. the live NFT owner (`account.rs:143-148`). These two definitions of "owner" can diverge after `position-nft::transfer`/`transfer_from`, since nothing in the NFT contract notifies the controller to resync `Account.owner`.

### Finding Description
The bug class of the incident — an account falling under an attacker's control — maps onto XOXNO Lending's two competing ownership sources:

- `Account.owner` is written once at mint (`account.rs:64-70`) and is the authority checked by `require_owner_or_delegate`, which every permissioned money verb reaches (`load_or_create_account` `AccountGuard::Migrate`/`Multiply` at `account.rs:101-109`, and the debt/supply/strategy modules calling it directly).
- The NFT contract stores transferable ownership under `NFTStorageKey::Owner(token_id)` and `transfer`/`transfer_from`/`approve` are stock OpenZeppelin methods with no controller callback (`contract.rs:131-173`).

When a user sells or transfers their position NFT, the on-chain NFT owner changes but `Account.owner` retains the seller's address. The seller (now an unprivileged ex-owner) still satisfies `caller == owner` in `require_owner_or_delegate` and can call `borrow`/`withdraw` on the account, while the buyer — who cannot satisfy that check and whose remedies (`add_delegate`, `renew_account`) require being the NFT owner only for those specific entrypoints — cannot move funds or stop the drain. Whether the controller resyncs `Account.owner` anywhere else in the codebase could not be fully confirmed within the available context; if any sync exists, this finding reduces to a freeze-only inconsistency.

### Impact Explanation
Theft of user funds: an ex-owner can `borrow` against the transferred account's collateral and `withdraw` remaining supply, extracting value the NFT buyer paid for. Alternatively (if `account.owner` is resynced in some paths), the mismatch still causes temporary freezing of funds for the legitimate owner whose `caller == account.owner` check fails on guard paths that were not updated.

### Likelihood Explanation
Requires only that an account NFT be transferred — an explicitly supported, in-scope operation (`position-nft::transfer`, `transfer_from`, `approve`). No privileged role, leaked key, or third-party cooperation is needed; the attacker is simply the seller executing a race/grief against the buyer, or deliberately retaining a backdoor after selling the position.

### Recommendation
Make the NFT owner the single source of truth: in `storage::get_account`/`require_owner_or_delegate`, resolve `account_owner` (live NFT `owner_of`) instead of the stored `Account.owner`, or overwrite `Account.owner` on every account load. Add a regression test asserting that after `position-nft::transfer`, the previous holder can no longer `borrow`/`withdraw` and the new holder can.

### Proof of Concept
1. Alice calls `controller::supply` with `account_id = 0`, creating account `N` owned by Alice and minting NFT `N` to her.
2. Alice calls `position-nft::transfer(alice → bob, N)` (in-scope, owner-authenticated).
3. Alice calls `controller::withdraw(caller = alice, account_id = N, ...)`. `require_owner_or_delegate` compares `caller` to `account.owner` (still Alice) at `account.rs:121` and passes; collateral leaves the account Bob now owns.
4. Bob's matching call fails the same check because `bob != account.owner`.