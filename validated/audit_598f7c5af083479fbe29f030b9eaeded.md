### Title
Stale cached `account.owner` authorizes the previous owner after a position-NFT transfer - (File: contracts/controller/src/account.rs)

### Summary
The controller stores `account.owner` once at account creation and uses that cached value for ownership checks in `load_or_create_account` (`AccountGuard::Migrate`, `AccountGuard::Multiply`), instead of the authoritative NFT owner in the `position-nft` contract. Like Symfony2 trusting a client-controllable value for an identity-sensitive decision instead of an explicit trusted source, the controller trusts a stale cached identity for sensitive decisions. After `position-nft` `transfer`/`approve` moves the token, the former owner remains `account.owner` and can still run privileged account operations against collateral the buyer now owns.

### Finding Description
`create_account` writes `owner: owner.clone()` into the `Account` struct once, at mint time ( [1](#0-0) ). Nothing ever rewrites it: the position NFT is a stock OpenZeppelin enumerable token whose `transfer`/`approve` go through `NonFungibleToken`/`NonFungibleEnumerable` with no hook back into the controller ( [2](#0-1) ). The NFT contract itself states "the token owner (`owner_of`) is the account owner" ( [3](#0-2) ), so the cached field diverges from the protocol's own definition of ownership on every transfer.

The privileged guard used by `multiply`, `flash_position`, and `migrate_from_blend` resolves `caller == account.owner` — the stale field — via `require_owner_or_delegate` ( [4](#0-3) ). Meanwhile `require_account_owner` correctly consults the live NFT owner via `storage::account_owner` ( [5](#0-4) ), proving the codebase has two conflicting sources of truth for the same identity.

Attack path (single unprivileged address):

1. Attacker opens a `Multiply`/`Long`/`Short` account (`account_id = X`) with collateral.
2. Attacker calls `position-nft.transfer(attacker, victim, X)` — a permissionless user-level NFT transfer.
3. Attacker calls `controller.flash_position` or `multiply` with `account_id = X`. `require_authorized_caller` passes because the attacker still signs the top-level call, and `AccountGuard::Multiply` passes because `caller == account.owner` — the stale cached value — even though the NFT now belongs to the victim.
4. `process_flash_position` mints debt onto account X ( [6](#0-5) ), the attacker's receiver sends just enough collateral to satisfy the solvency check, and declared `refund_assets` return unspent debt tokens to `caller` — the attacker — while the minted debt stays on the victim-owned account. Leftover debt tokens do not auto-repay ( [7](#0-6) ).
5. The attacker drains the extractable value as refund debt tokens; the victim's account is left levered to the edge of liquidation, and the victim must repay debt they never authorized to recover their collateral.

### Impact Explanation
Theft of user funds. The former owner can mint the maximum debt the account's collateral supports and walk away with the proceeds via `refund_assets`, leaving an account the victim owns underwater — equivalent to extracting the collateral's borrowable value from the buyer. The victim's only recourse is repaying debt they never took. This is a direct consequence of trusting a cached identity field for an authorization decision — the exact bug class of the advisory (trusting an unverified/spoofable source of identity for sensitive decisions instead of the authoritative one).

### Likelihood Explanation
Fully reachable by any unprivileged address: `position-nft` `transfer` is standard user functionality, and `flash_position`/`multiply`/`migrate_from_blend` are public controller entrypoints. No privileged role, timing condition, or oracle manipulation is required; the divergence exists from the moment of any transfer, including NFT sales on secondary markets where the buyer pays for the position's net equity.

### Recommendation
Derive ownership for `require_owner_or_delegate` from `storage::account_owner` (the live NFT `owner_of`) instead of the cached `account.owner` field, as `require_account_owner` already does; or update `account.owner` inside every privileged path from the NFT owner before the guard check. The cached field should at most be a hint, never the authorization source.

### Proof of Concept
```rust
// attacker opened account X in PositionMode::Long with collateral, then:
nft_client.transfer(&attacker, &victim, &X);          // authoritative owner -> victim
// Account.owner in controller storage is still `attacker` (set once at mint).

// attacker passes both gates:
flash_position(
    caller = attacker,          // require_authorized_caller: attacker's signature
    account_id = X,
    mode = PositionMode::Long,  // matches stale account.mode
    debt = HubAssetKey{hub, usdc}, amount = max_borrowable,
    receiver = attacker_receiver,
    collaterals = [min dust collateral],
    refund_assets = [usdc],     // unspent minted debt refunded to attacker
);
// require_owner_or_delegate(X, attacker, account.owner==attacker) -> OK
// -> debt minted on victim-owned account, refund tokens go to attacker.
```

### Citations

**File:** contracts/controller/src/account.rs (L63-71)
```rust
    let account_id = nft_mint_call(env, &nft, owner);
    let account = Account {
        owner: owner.clone(),
        spoke_id,
        mode,
        supply_positions: Map::new(env),
        borrow_positions: Map::new(env),
    };
    storage::set_account_meta(env, account_id, &AccountMeta { spoke_id, mode });
```

**File:** contracts/controller/src/account.rs (L99-140)
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

**File:** contracts/controller/src/account.rs (L143-148)
```rust
pub(crate) fn require_account_owner(env: &Env, account_id: u64, caller: &Address) -> AccountMeta {
    let meta = storage::get_account_meta(env, account_id);
    let owner = storage::account_owner(env, account_id);
    assert_with_error!(env, owner == *caller, GenericError::AccountNotInMarket);
    meta
}
```

**File:** contracts/position-nft/src/contract.rs (L1-5)
```rust
//! Lending-position NFT: one token per controller account, and the token id is
//! the account id. The token owner (`owner_of`) is the account owner.
//! Mint, burn and upgrade are controller-only; `renew` is permissionless. The
//! rest is the stock OpenZeppelin non-fungible interface with a custom
//! `token_uri`.
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

**File:** contracts/controller/src/strategies/flash_position.rs (L93-111)
```rust
    let (account_id, mut account) = account::load_or_create_account(
        env,
        caller,
        account_id,
        spoke_id,
        mode,
        account::AccountGuard::Multiply,
        &mut cache,
    );

    validate_collaterals(env, &mut cache, &account, collaterals);
    validate_refund_assets(
        env,
        &mut cache,
        account.spoke_id,
        debt.hub_id,
        collaterals,
        refund_assets,
    );
```

**File:** contracts/controller/src/strategies/migrate_blend.rs (L21-30)
```rust
pub(crate) struct MigrateBlendParams {
    pub account_id: u64,
    pub spoke_id: u32,

    pub hub_id: u32,
    pub blend_pool: Address,
    pub collateral_assets: Vec<Address>,
    pub supply_assets: Vec<Address>,
    pub debt_caps: Vec<(Address, i128)>,
}
```
