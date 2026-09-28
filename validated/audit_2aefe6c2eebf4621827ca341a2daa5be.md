### Title
Stale `Account.owner` cached at mint lets a previous NFT holder retain account authority after `transfer` — the CVE-2019-12749 "reused credential under a wrong principal" analog - (File: contracts/controller/src/account.rs)

### Summary
CVE-2019-12749 is an indirection bug: a mutable reference (symlink) causes a privileged actor to reuse a credential that now stands for a different principal, yielding an authentication bypass. The same shape exists in the controller: account identity is cached in `Account.owner` at mint time, while live ownership lives in the position-NFT. Paths that consult the stale copy can treat the *former* NFT holder as the current principal.

### Finding Description
`create_account_with` stores `owner` inside the `Account` struct at mint time ( [1](#0-0) ), and the NFT itself is freely transferable via the OpenZeppelin enumerable implementation ( [2](#0-1) ). Nothing observed refreshes `account.owner` on transfer.

Two different sources of truth are then used for authorization:

- `require_account_owner` correctly checks live NFT ownership via `storage::account_owner` ( [3](#0-2) ).
- `is_owner_or_delegate` / `require_owner_or_delegate` instead compare `caller` against the *cached* `account.owner`, and resolve delegates under that cached owner key ( [4](#0-3) ).

`load_or_create_account` invokes `require_owner_or_delegate` under `AccountGuard::Migrate` and `AccountGuard::Multiply` ( [5](#0-4) ), which gate `migrate_from_blend` and `multiply` — entrypoints reachable by any unprivileged address. After a victim transfers the position NFT, the stored `account.owner` still names the *previous* holder, so that previous holder (or a manager the previous holder delegated via `add_delegate`, keyed under `(account_id, old_owner)` at [6](#0-5) ) continues to satisfy owner checks against an account they no longer own.

### Impact Explanation
A seller who transfers the position NFT retains operational authority over the buyer's account on every path that resolves identity through `account.owner` rather than the live NFT owner — including `multiply`, `migrate_from_blend`, `swap_debt`/`swap_collateral`/`repay_debt_with_collateral` delegate checks, and delegate management semantics. Depending on which guard each path applies, the former owner can enter new debt/leverage positions against collateral the buyer expects to control, or keep dormant delegate grants alive. This is theft/manipulation of the buyer's position via an attacker-reachable entrypoint — the same outcome class as the dbus cookie reuse (a credential accepted as proof of a uid it no longer represents).

Caveat: I was unable to fully trace which guard each entrypoint in `lib.rs` applies (debt.rs/supply.rs use a mixture of `require_account_owner` and owner-field reads). If every value-moving path ultimately routes through `require_account_owner`, the practical impact narrows to delegate-state confusion; if `Migrate`/`Multiply`-style guards apply to funded accounts, impact is High.

### Likelihood Explanation
Requires only an NFT `transfer`/`transfer_from` (in-scope, unprivileged) followed by a call to a stale-owner-guarded entrypoint. Secondary-market sale of positions is the expected use of the NFT, so the precondition is realistic. Exploitability hinges on the guard selection per entrypoint noted above.

### Recommendation
Use a single source of truth for identity: derive the current owner exclusively from `storage::account_owner` (the NFT `Owner` entry) in `is_owner_or_delegate`/`require_owner_or_delegate`, or update `account.owner` on every transfer hook. Also key delegate grants to the account id alone and clear them on NFT transfer, so a previous owner's `add_delegate` grants cannot survive the sale.

### Proof of Concept
1. Alice calls `supply(account_id = 0, ...)`; `create_account` mints NFT id `N` to Alice and stores `Account { owner: Alice, ... }`.
2. Alice calls `add_delegate(N, M)` granting active manager `M`.
3. Alice sells/transfers NFT `N` to Bob via `position-nft::transfer`.
4. `storage::account_owner(N)` now returns Bob, but `Account.owner` still equals Alice.
5. Alice (or `M`) calls a `require_owner_or_delegate`-guarded entrypoint (e.g., `multiply`/`migrate_from_blend`) with `account_id = N`; `caller == account.owner` succeeds against the stale field, letting Alice act on Bob's account.

### Citations

**File:** contracts/controller/src/account.rs (L64-66)
```rust
    let account = Account {
        owner: owner.clone(),
        spoke_id,
```

**File:** contracts/controller/src/account.rs (L101-109)
```rust
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
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

**File:** contracts/controller/src/account.rs (L143-147)
```rust
pub(crate) fn require_account_owner(env: &Env, account_id: u64, caller: &Address) -> AccountMeta {
    let meta = storage::get_account_meta(env, account_id);
    let owner = storage::account_owner(env, account_id);
    assert_with_error!(env, owner == *caller, GenericError::AccountNotInMarket);
    meta
```

**File:** contracts/controller/src/account.rs (L249-264)
```rust
    caller.require_auth();
    require_account_owner(env, account_id, caller);
    if add {
        // Reject dormant grants that could gain authority on later manager activation.
        assert_with_error!(
            env,
            storage::get_position_manager(env, delegate).is_some_and(|c| c.is_active),
            GenericError::NotAuthorized
        );
    }

    let changed = if add {
        storage::add_delegate(env, account_id, caller, delegate)
    } else {
        storage::remove_delegate(env, account_id, caller, delegate)
    };
```

**File:** contracts/position-nft/src/contract.rs (L132-133)
```rust
impl NonFungibleToken for PositionNft {
    type ContractType = Enumerable;
```
