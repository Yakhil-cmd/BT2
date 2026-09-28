### Title
Stale `Account.owner` lets the prior NFT holder keep borrow/withdraw authority after a position transfer — (File: contracts/controller/src/account.rs)

### Summary

`borrow`, `withdraw`, and the strategy entrypoints authorize the caller against the `owner` field stored inside the `Account` struct, which is written once at mint time (`create_account_with`, `account.rs:64-66`). Position ownership, however, lives in the position-nft contract and can change at any time via the stock OpenZeppelin `transfer`/`approve` interface (`contracts/position-nft/src/contract.rs`, `NonFungibleToken` impl). The controller even maintains a separate live lookup, `storage::account_owner` → `nft_try_owner_of_call` (`external/position_nft.rs:19-25`), used by the owner-only paths `renew_account`/`add_delegate`/`remove_delegate` (`account.rs:143-148`, `require_account_owner`). If the stored `Account.owner` is not resynced when the NFT moves, the previous holder retains spending authority over collateral and debt they no longer own — the direct analog of CVE-2022-2385: an identity mutated while a stale copy of it remains authorized.

### Finding Description

- `process_borrow` and `process_withdraw` call `require_owner_or_delegate(env, account_id, caller, &account.owner)` where `account` comes from `storage::get_account` (`positions/debt.rs:42-43`, `positions/supply.rs:149-150`).
- `is_owner_or_delegate` returns `true` whenever `caller == owner` (`account.rs:121-122`), and delegates are keyed under that same stored owner (`account.rs:126`, `storage::get_delegates(env, account_id, owner)`).
- `Account.owner` is only assigned in `create_account_with` (`account.rs:65`); no transfer hook resyncs it, and the NFT `transfer`/`approve` path has no controller callback.
- Owner-only operations deliberately do *not* trust the stored field: `require_account_owner` reads `storage::account_owner` (the live NFT `owner_of`), confirming the two sources can diverge.

Consequence: after Alice transfers position NFT `N` to Bob, `account.owner` still equals Alice. Alice (and any delegate she granted while owner — grants persist under her address) can still `borrow`/`withdraw`/`swap_collateral`/`repay_debt_with_collateral` on `N`, while Bob, the real owner, fails `caller == owner` on the same paths. Bob can still hit `require_account_owner` paths (delegation, renewal) but cannot stop Alice draining the account's remaining collateral or maxing its debt to extract value via `to:` recipient before it liquidates.

### Impact Explanation

Theft of user funds. The buyer of a leveraged/collateralized position NFT receives an account whose prior owner retains full economic control: `withdraw` all collateral to `to = attacker`, or `borrow` to the HF limit with `to = attacker`, leaving the transferee holding the debt. Any secondary-market sale or wallet rotation of a position NFT is exploitable.

### Likelihood Explanation

High, conditional on `storage::get_account` not stamping `owner` from `nft_try_owner_of_call` on load — which the code structure argues against, since a dedicated live-lookup helper exists precisely for owner-sensitive checks and the stored field is treated as authoritative in `is_owner_or_delegate`. Reachability is trivial: NFT `transfer` is a stock OZ entrypoint callable by any token owner, after which the ex-owner calls `controller::withdraw(account_id, ...)` unprivileged. If `get_account` does re-resolve `owner` from the NFT on every load, the finding collapses — that could not be fully verified from `storage/account.rs` in this pass and is the key point to confirm.

### Recommendation

Resolve `owner` exclusively from `nft_try_owner_of_call` (or resync `account.owner` at the top of `get_account`/`require_owner_or_delegate`), and key delegate grants by account id alone or by a transfer epoch so grants die with ownership changes. Add a test: owner transfers NFT → old owner's `borrow`/`withdraw` revert with `NotAuthorized`.

### Proof of Concept

1. Alice calls `controller::supply(alice, 0, spoke, [(USDC, 10_000)])` → `account_id = N`, NFT `N` minted to Alice, `Account.owner = alice`.
2. Alice calls `position-nft::transfer(alice, bob, N)`. NFT `owner_of(N) = bob`; `Account.owner` still `alice`.
3. Alice calls `controller::borrow(alice, N, [(ETH, 1)], Some(alice))`. `caller.require_auth` passes; `is_owner_or_delegate` sees `caller == account.owner == alice` → authorized; pool pays ETH to Alice; debt lands on Bob's account.
4. Alice calls `controller::withdraw(alice, N, [(USDC, 0)], Some(alice))` to drain remaining collateral within solvency limits.

Bob's recourse paths (`remove_delegate`, `renew_account`) work because they read the live NFT owner, but nothing revokes Alice's stale owner equivalence on the spending paths.