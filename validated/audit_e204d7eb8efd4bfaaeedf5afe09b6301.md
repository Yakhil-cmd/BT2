### Title
Stale `account.owner` grants the previous NFT holder full spending authority after a `position-nft` transfer — broken access control enabling theft of collateral - (File: contracts/controller/src/account.rs)

### Summary
The controller authenticates spending authority for `borrow`, `withdraw`, `multiply`, `flash_position`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and `migrate_from_blend` through `require_owner_or_delegate`, which compares the caller against `account.owner` — a field written once at account creation inside the stored `Account` struct. The `position-nft` contract's `transfer`/`transfer_from` are stock OpenZeppelin Enumerable methods: they move the NFT with only `from`/`spender` authorization and invoke nothing on the controller, so `account.owner` is never resynchronized. After an account NFT changes hands, the recorded owner remains the previous holder.

### Finding Description
`load_or_create_account` for `Migrate`/`Multiply` guards and the supply/borrow flows call `require_owner_or_delegate(env, account_id, caller, &account.owner)` [1](#0-0) . `is_owner_or_delegate` returns `true` whenever `caller == owner`, where `owner` is the stale stored field [2](#0-1) . By contrast, `require_account_owner` (used by `renew_account`, `add_delegate`, `remove_delegate`) reads live NFT ownership via `storage::account_owner` [3](#0-2)  — proving the codebase maintains two divergent notions of "owner" and only one of them tracks the NFT. Grep across `contracts/controller/src` shows no write path that updates `Account.owner` after `create_account_with` sets it [4](#0-3) , and the permissionless-entrypoints registry confirms `position-nft::transfer`/`transfer_from` are self-contained stock methods requiring only holder/spender auth [5](#0-4) .

An attacker who sells or transfers their account NFT retains the `account.owner` credential: they can keep calling `withdraw(account_id, ...)` to pull out every unit of collateral that solvency allows, or `borrow` to the liquidation threshold and let the position be liquidated — spending authority over assets that now belong to the buyer.

### Impact Explanation
Theft of user funds and freezing of funds. The previous holder drains withdrawable collateral from an account the buyer just paid for (theft). Simultaneously, the legitimate new NFT owner fails `require_owner_or_delegate` on `withdraw`/`borrow` (their address ≠ stale `account.owner`, and old delegates are correctly deactivated on transfer) — they cannot manage their own position at all (freezing). This mirrors the report's class: an authorization decision rests on a credential that was not revoked when the underlying authority (NFT ownership) moved.

### Likelihood Explanation
Requires a victim to acquire an account NFT (secondary sale, OTC deal, or compromised approval flow) — the NFT exists precisely to make positions transferable. A single unprivileged address (the seller) executes the attack with ordinary `withdraw`/`borrow` calls after settlement of the transfer; no timing, oracle, or privileged access needed. The previous owner's delegate list also remains keyed under the old owner in `storage::get_delegates(env, account_id, owner)`, so stale delegates could regain reach through the same stale field.

### Recommendation
Derive spending authority from live NFT ownership everywhere: inside `require_owner_or_delegate` (or at every call site feeding it `&account.owner`), resolve `storage::account_owner(env, account_id)` — the same source `require_account_owner` uses — instead of the cached `Account.owner` field, and key delegate lookups under that live owner. Alternatively, drop `owner` from the stored `Account` struct entirely to remove the possibility of divergence.

### Proof of Concept
1. Alice creates account `A` via `supply` (account_id 0) with 1,000 USDC collateral; `account.owner = ALICE`, NFT `A` minted to Alice.
2. Alice calls `position-nft::transfer(ALICE, BOB, A)`. The stock method only requires Alice's auth; the controller is never invoked, so `Account.owner` still reads `ALICE` while `storage::account_owner(A)` now returns `BOB`.
3. Alice calls `controller::withdraw(ALICE, A, USDC_key, i128::MAX, ...)`. `withdraw` reaches `require_owner_or_delegate(env, A, ALICE, &account.owner)`; `caller == account.owner` passes, Alice signs `require_auth`, collateral is paid to Alice.
4. Bob calls `controller::withdraw(BOB, A, ...)`; `BOB != account.owner (ALICE)` and Bob is not a listed delegate → `GenericError::NotAuthorized`. Bob owns the NFT but cannot touch the (now drained) position.

Caveat: I verified no `account.owner` write exists outside creation via repository-wide grep, but did not exhaustively read every position-flow entrypoint; if any flow rewrites `Account.owner` from the live NFT on each call, the window narrows to paths that skip that resync.

### Citations

**File:** contracts/controller/src/account.rs (L64-71)
```rust
    let account = Account {
        owner: owner.clone(),
        spoke_id,
        mode,
        supply_positions: Map::new(env),
        borrow_positions: Map::new(env),
    };
    storage::set_account_meta(env, account_id, &AccountMeta { spoke_id, mode });
```

**File:** contracts/controller/src/account.rs (L99-110)
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
```

**File:** contracts/controller/src/account.rs (L115-127)
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
```

**File:** contracts/controller/src/account.rs (L143-148)
```rust
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
