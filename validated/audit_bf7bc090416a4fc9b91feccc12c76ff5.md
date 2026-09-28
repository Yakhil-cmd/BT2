### Title
Stale `Account.owner` lets a previous NFT holder keep full spending authority after transferring the position NFT — (File: contracts/controller/src/account.rs)

### Summary
The HAX advisory pattern — endpoints that verify *authentication* but not *authorization over the resource* — maps onto the XOXNO controller's spending paths. `borrow`, `withdraw`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`, and `flash_position` all gate on `require_owner_or_delegate`, which compares `caller` against the **stored** `Account.owner` field, not the current NFT owner. `Account.owner` is set once at account creation and is never rewritten afterward, so after a `position-nft` `transfer`/`transfer_from`, the seller remains "owner" for every spending check and can drain the account the buyer just acquired.

### Finding Description
`create_account_with` stamps `Account { owner: owner.clone(), ... }` when the NFT is minted, and nothing in `contracts/controller/src` ever assigns `account.owner` again [1](#0-0) . The spending guard is a pure identity comparison against that stale field: [2](#0-1) 

`is_owner_or_delegate` returns `true` whenever `caller == owner` (the stored field), so `require_owner_or_delegate` passes for the *previous* NFT holder — they can legitimately `require_auth` their own address, exactly the "authenticated but not authorized" flaw in the HAX report. The codebase itself recognizes the distinction: `require_account_owner` exists to check the **live** NFT owner via `storage::account_owner`, but it is used only by `renew_account` and the delegate setters — not by any path that moves funds [3](#0-2) . The declared auth model even acknowledges that NFT transfer changes account ownership ("delegate grants from the previous owner go inactive"), yet the owner check that matters for fund movement never consults it [4](#0-3) . Callers reach this through `load_or_create_account`'s `Multiply`/`Migrate` guards and the direct `require_owner_or_delegate` calls in `positions/debt.rs`, `positions/supply.rs`, and the strategy modules [5](#0-4) .

### Impact Explanation
Theft of user funds. After selling or transferring a position NFT, the former holder calls `withdraw(account_id, payments, to=Some(self))` or `borrow(account_id, ...)`; `caller.require_auth` succeeds (they sign), `caller == account.owner` succeeds (stale field), and collateral or borrowed assets leave the buyer's account. The buyer's recourse is limited to racing the ex-owner. This is precisely the "authenticated attacker interacts with another user's resource" class from CVE-2025-54378.

### Likelihood Explanation
Deterministic and trivially reachable: one ordinary address, one `position-nft::transfer_from` (or sale that transfers the NFT), then one `withdraw`. No privileged role, price manipulation, or exotic route is required. Any marketplace or OTC flow that moves the NFT creates the window; the ex-owner retains authority until they exercise it.

### Recommendation
Make spending authority derive from live NFT ownership, not the stored field. Either (a) replace the stored-owner comparison in `require_owner_or_delegate` with `storage::account_owner(env, account_id)` (the same source `require_account_owner` uses), or (b) add a hook that resyncs `Account.owner` on NFT transfer — noting position-nft transfer paths don't call back into the controller today. Applying (a) inside `is_owner_or_delegate` fixes all downstream callers uniformly, and the delegate map already keys grants under `owner`, so the lookup naturally resolves delegates under the current owner.

### Proof of Concept
1. Alice supplies collateral via `supply`; `create_account_with` stores `Account.owner = Alice` and mints NFT `id` to her.
2. Alice calls `position-nft::transfer(Alice → Bob, id)`. NFT owner is now Bob; `Account.owner` still reads Alice — no code path rewrites it.
3. Alice calls `controller::withdraw(caller=Alice, account_id=id, payments=[...], to=Some(Alice))`. `Alice.require_auth` succeeds; `is_owner_or_delegate` returns `true` on `caller == account.owner` [6](#0-5) ; collateral transfers to Alice.
4. Alternatively Alice calls `borrow` against Bob's collateral up to the LTV limit; Bob discovers the account drained or newly indebted.

Caveat: I verified that `Account.owner` is written only at creation in the indexed source and that `require_account_owner` uses a separate live-ownership lookup; I could not exhaustively confirm every storage-write site, but the grep for `account.owner =` returned no reassignment outside construction, and the delegate system's keying under `owner` is consistent with the stale-owner design.

### Citations

**File:** contracts/controller/src/account.rs (L64-74)
```rust
    let account = Account {
        owner: owner.clone(),
        spoke_id,
        mode,
        supply_positions: Map::new(env),
        borrow_positions: Map::new(env),
    };
    storage::set_account_meta(env, account_id, &AccountMeta { spoke_id, mode });

    (account_id, account)
}
```

**File:** contracts/controller/src/account.rs (L99-112)
```rust
    match guard {
        AccountGuard::Supply => require_spoke_match(env, &account, spoke_id),
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
        }
    }
    (account_id, account)
}
```

**File:** contracts/controller/src/account.rs (L115-140)
```rust
pub(crate) fn is_owner_or_delegate(
    env: &Env,
    account_id: u64,
    caller: &Address,
    owner: &Address,
) -> bool {
    if caller == owner {
        return true;
    }
    let active_manager =
        storage::get_position_manager(env, caller).is_some_and(|config| config.is_active);
    active_manager && storage::get_delegates(env, account_id, owner).contains(caller)
}

/// Requires the owner or a registered, active manager delegated by that owner.
pub(crate) fn require_owner_or_delegate(
    env: &Env,
    account_id: u64,
    caller: &Address,
    owner: &Address,
) {
    if is_owner_or_delegate(env, account_id, caller, owner) {
        return;
    }
    panic_with_error!(env, GenericError::NotAuthorized);
}
```

**File:** contracts/controller/src/account.rs (L142-148)
```rust
/// Returns metadata after verifying that `caller` currently owns the account NFT.
pub(crate) fn require_account_owner(env: &Env, account_id: u64, caller: &Address) -> AccountMeta {
    let meta = storage::get_account_meta(env, account_id);
    let owner = storage::account_owner(env, account_id);
    assert_with_error!(env, owner == *caller, GenericError::AccountNotInMarket);
    meta
}
```

**File:** scripts/permissionless_entrypoints.txt (L111-112)
```text
position-nft::transfer | caller-auth | INV-AUTH-02 | from.require_auth authorizes the move and the stock update rejects any from that is not the token owner, so only the holder can move the whole account; delegate grants from the previous owner go inactive.
position-nft::transfer_from | caller-auth | INV-AUTH-02 | spender.require_auth authorizes the move, which needs spender to be the owner, the token's live approved address, or an operator the owner approved for all; the stock update then rejects any from that is not the owner, and the transfer clears the token approval.
```
