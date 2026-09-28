### Title
Stale delegate authorization reactivates when position NFT ownership returns - (File: contracts/controller/src/storage/account.rs)

### Summary
Controller delegates are keyed only by `account_id` and `granted_by`; transferring the position NFT temporarily disables an old owner's grants, but the same grants become valid again if the NFT ever returns to that owner. [1](#0-0) 

### Finding Description
The controller treats a caller as authorized when the caller is either the current NFT owner or an active position manager present in `get_delegates`. [2](#0-1) 

`get_delegates` returns the stored list whenever its `granted_by` field equals the current NFT owner, but does not distinguish the current ownership session from a previous period in which that same address owned the NFT. [1](#0-0) 

The stored grant survives while another address owns the NFT, because ordinary NFT ownership changes do not remove `ControllerKey::Delegates(account_id)`. [3](#0-2) 

If the NFT later returns to the original owner, the dormant grant is accepted again without any fresh authorization from that owner. [4](#0-3) 

The stale delegate can then use owner/delegate-gated account functions such as `borrow`, which can send proceeds to an arbitrary `to` address, or `withdraw`, which can send withdrawn collateral to an arbitrary `to` address. [5](#0-4) 

### Impact Explanation
A previously delegated manager can drain an account after its NFT completes an ownership round trip back to the delegating owner. [5](#0-4) 

The attacker can withdraw available collateral to itself and borrow up to the account's risk limits, leaving the restored owner with reduced collateral and protocol debt. [5](#0-4) 

This permits theft of user funds because the authorization was granted for an earlier ownership period but is replayed after ownership changed away and back. [1](#0-0) 

### Likelihood Explanation
The attack requires an active position manager to have been delegated before the NFT transfer, and requires the NFT eventually to return to that same owner. [1](#0-0) 

Those conditions can arise through secondary-market position trading, temporary custody, collateralized transfers, or a mistaken transfer followed by return. [6](#0-5) 

Because a valid exploit needs the ownership round trip rather than only a direct unauthorized call, the issue is less immediately reachable than a general missing-auth flaw, but it has a direct theft path once the dormant grant reactivates. [5](#0-4) 

### Recommendation
Invalidate all controller delegate grants whenever the position NFT changes owner, rather than merely filtering them by the current owner address. [1](#0-0) 

A robust design is to make the position NFT notify the controller during transfer so the controller deletes `ControllerKey::Delegates(account_id)`, or to include an ownership-generation value in each grant that changes on every transfer. [7](#0-6) 

Do not rely on `remove_delegate` as the sole cleanup mechanism, because a new owner cannot be expected to remove a stale grant stamped by a prior owner before that prior owner receives the NFT again. [8](#0-7) 

### Proof of Concept
1. Alice owns account `42` and calls `add_delegate(alice, 42, mallory)`, where `mallory` is an active position manager. [9](#0-8) 
2. Alice transfers the position NFT for token/account `42` to Bob; `get_delegates(env, 42, bob)` rejects Mallory because Alice's stored `granted_by` no longer equals the current owner. [1](#0-0) 
3. Bob later transfers the same NFT back to Alice without Alice calling `add_delegate` again. [6](#0-5) 
4. `get_delegates(env, 42, alice)` again returns Mallory because the old `DelegateGrant` still has `granted_by == alice`. [4](#0-3) 
5. Mallory calls `borrow(mallory, 42, borrows, Some(mallory))` or `withdraw(mallory, 42, withdrawals, Some(mallory))`; the owner-or-delegate check accepts the stale grant and sends value to Mallory. [5](#0-4)

### Citations

**File:** contracts/controller/src/storage/account.rs (L174-181)
```rust
/// Returns grants stamped by `owner`, or an empty list. Ownership changes
/// invalidate a previous owner's grants without deleting them.
pub(crate) fn get_delegates(env: &Env, account_id: u64, owner: &Address) -> Vec<Address> {
    get_user::<DelegateGrant>(env, &ControllerKey::Delegates(account_id))
        .filter(|grant| grant.granted_by == *owner)
        .map(|grant| grant.delegates)
        .unwrap_or_else(|| Vec::new(env))
}
```

**File:** contracts/controller/src/storage/account.rs (L185-199)
```rust
fn set_delegates(env: &Env, account_id: u64, owner: &Address, delegates: &Vec<Address>) {
    let key = ControllerKey::Delegates(account_id);
    if delegates.is_empty() {
        env.storage().persistent().remove(&key);
    } else {
        set_user(
            env,
            &key,
            &DelegateGrant {
                granted_by: owner.clone(),
                delegates: delegates.clone(),
            },
        );
    }
}
```

**File:** contracts/controller/src/storage/account.rs (L223-239)
```rust
/// Removes a live delegate and reports whether it changed the list.
/// Deletes stale grants but returns false, preventing those grants from
/// reactivating if the NFT returns to their original owner.
pub(crate) fn remove_delegate(
    env: &Env,
    account_id: u64,
    owner: &Address,
    delegate: &Address,
) -> bool {
    let key = ControllerKey::Delegates(account_id);
    let Some(grant) = get_user::<DelegateGrant>(env, &key) else {
        return false;
    };
    if grant.granted_by != *owner {
        env.storage().persistent().remove(&key);
        return false;
    }
```

**File:** contracts/controller/src/account.rs (L114-127)
```rust
/// Accepts the owner or a registered, active manager delegated by that owner.
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

**File:** contracts/controller/src/account.rs (L228-264)
```rust
/// Requires the NFT owner to grant an active manager access; renews instance TTL.
pub(crate) fn add_delegate(env: &Env, caller: Address, account_id: u64, delegate: Address) {
    storage::renew_controller_instance(env);
    set_account_delegate(env, &caller, account_id, &delegate, true);
}

/// Requires the NFT owner to revoke manager access; renews instance TTL.
pub(crate) fn remove_delegate(env: &Env, caller: Address, account_id: u64, delegate: Address) {
    storage::renew_controller_instance(env);
    set_account_delegate(env, &caller, account_id, &delegate, false);
}

/// Authenticates the NFT owner and updates delegates; grants require an active
/// manager. Emits an event only when the current owner's delegate list changes.
fn set_account_delegate(
    env: &Env,
    caller: &Address,
    account_id: u64,
    delegate: &Address,
    add: bool,
) {
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

**File:** contracts/controller/src/lib.rs (L104-128)
```rust
    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }

    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }
```

**File:** contracts/position-nft/src/contract.rs (L131-173)
```rust
#[contractimpl(contracttrait)]
impl NonFungibleToken for PositionNft {
    type ContractType = Enumerable;

    /// `{stored base_uri}{token_id}?isStatic=true&chain=STELLAR`
    ///
    /// Panics with the OZ `NonExistentToken` error for burned or never-minted
    /// ids, matching the stock behavior.
    fn token_uri(e: &Env, token_id: u32) -> String {
        let _owner = Base::owner_of(e, token_id);

        let base = Base::base_uri(e);
        let base_len = base.len() as usize;
        // OZ `set_metadata` caps the base at `MAX_BASE_URI_LEN` (200 bytes):
        // 200 + 10 digits (u32 max) + 28-byte suffix fits in 256.
        let mut buf = [0u8; 256];
        base.copy_into_slice(&mut buf[..base_len]);
        let mut len = base_len;
        // Decimal digits, most significant first. token_id >= 1 always
        // (id 0 is consumed at construction), so no zero special-case.
        let mut digits = [0u8; 10];
        let mut n = token_id;
        let mut count = 0usize;
        while n > 0 {
            digits[count] = b'0' + (n % 10) as u8;
            n /= 10;
            count += 1;
        }
        while count > 0 {
            count -= 1;
            buf[len] = digits[count];
            len += 1;
        }
        for b in TOKEN_URI_SUFFIX.bytes() {
            buf[len] = b;
            len += 1;
        }
        String::from_bytes(e, &buf[..len])
    }
}

#[contractimpl(contracttrait)]
impl NonFungibleEnumerable for PositionNft {}
```
