### Title
Position NFT transferred or minted to a contract that cannot produce Soroban auth permanently freezes the lending account - ([File: contracts/position-nft/src/contract.rs](contracts/position-nft/src/contract.rs))

### Summary
The position NFT implements the stock OpenZeppelin `transfer`/`transfer_from` with no receiver-capability check, and the controller mints accounts to `owner` without checking that `owner` can ever authorize again. On Soroban a contract address can only satisfy `require_auth` for its own address while it is itself executing; a contract that does not expose a method which calls `require_auth` (or that cannot be invoked to do so) can never sign. Any lending position owned by such an address is permanently bricked: all collateral and debt are frozen, and no protocol path recovers them.

### Finding Description
- `PositionNft::mint` mints to an arbitrary `to` with only the controller's auth; it performs no check on the recipient [1](#0-0) 
- The inherited `transfer(from, to, token_id)` requires only `from.require_auth()`; there is no Soroban equivalent of `safeTransferFrom`/`IERC721Receiver` — the `to` address is never validated as able to authorize [2](#0-1) 
- The controller resolves authority purely through NFT ownership plus `require_auth` (`is_owner_or_delegate` resolves `nft_try_owner_of_call`, then the owner/delegate must authorize). An owner that cannot produce auth fails every owner-gated verb: `withdraw`, `borrow`, `repay`, `transfer` back out, etc. [3](#0-2) 
- `transfer` revokes the prior owner and all delegates atomically, so the previous owner cannot rescue the account either [4](#0-3) 
- The same applies at mint time: `create_account_with` mints to `owner`, and paths like `SeizeMode::Credit` liquidation receivers or a contract calling `supply` with `account_id = 0` can place a fresh account under an address that may never be able to authorize [5](#0-4) 

### Impact Explanation
Permanent freezing of user funds. Once the token sits on an auth-incapable contract address, every owner-gated controller entrypoint (`withdraw`, `repay`, `borrow`, `swap_*`, `multiply`, NFT `transfer`) reverts on the missing auth, and the previous owner is fully revoked. The only remaining movement is permissionless liquidation of an unhealthy account — solvent collateral-only positions are frozen forever. This is exactly the `_mint` vs `_safeMint` lock-up class from the reference report, mapped to Soroban's auth model.

### Likelihood Explanation
Medium. Requires a user (or an integrating contract) to `transfer`/`transfer_from` a position to a contract that lacks an auth-forwarding method, or to act as `caller`/`receiver` from such a contract when an account is created (supply with `account_id = 0`, `SeizeMode::Credit` receiver account, `flash_position` opening an account for the receiver). Self-inflicted user error, but reachable by any unprivileged address through allowed entrypoints, with irreversible consequences and no admin recovery path.

### Recommendation
Where the protocol itself chooses the recipient (mint via `supply`, `flash_position`, `SeizeMode::Credit` receivers), restrict `owner`/`to` to addresses that can authorize — practically, either mint to the authenticated caller only, or require `to.require_auth()` at mint/transfer time so the receiving contract must affirmatively opt in inside the same transaction. For user-initiated `transfer`, requiring `to.require_auth()` gives a `safeTransfer`-equivalent guarantee on Soroban: the receiver proves it can authorize before taking ownership.

### Proof of Concept
1. Alice supplies USDC via `controller.supply(caller=alice, account_id=0, ...)`; NFT `token_id = N` minted to Alice.
2. Alice calls `position_nft.transfer(alice, C, N)` where `C` is a contract exposing no method that calls `require_auth` and no method invoking `transfer`.
3. `storage::account_owner` now resolves to `C`; Alice and all her delegates are revoked.
4. Any `withdraw`/`repay`/`transfer` call needs `C`'s auth, which `C` can never produce → the collateral is frozen permanently; only liquidation can ever touch it.

### Citations

**File:** contracts/position-nft/src/contract.rs (L68-76)
```rust
    pub fn mint(e: &Env, to: Address) -> u32 {
        controller(e).require_auth();
        renew_instance(e);
        let token_id = Enumerable::sequential_mint(e, &to);
        // sequential_mint writes Owner/Balance at the network minimum TTL; lift
        // them to the user window so a new position does not archive early.
        extend_user_persistent_ttl(e, &to, token_id);
        token_id
    }
```

**File:** contracts/position-nft/README.md (L62-63)
```markdown
| `transfer` | `fn transfer(e: &Env, from: Address, to: Address, token_id: u32)` | `from` must authorize | Moves the position to `to` |
| `transfer_from` | `fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, token_id: u32)` | `spender` must authorize and be `from`, approved for the token, or an operator for `from` | Moves the position to `to` |
```

**File:** contracts/controller/src/external/position_nft.rs (L19-25)
```rust
pub(crate) fn nft_try_owner_of_call(env: &Env, nft: &Address, account_id: u64) -> Option<Address> {
    let token_id = u32::try_from(account_id).ok()?;
    match PositionNftClient::new(env, nft).try_owner_of(&token_id) {
        Ok(Ok(owner)) => Some(owner),
        _ => None,
    }
}
```

**File:** contracts/controller/tests/helpers/account.rs (L400-432)
```rust
    env.as_contract(&contract_id, || {
        crate::storage::set_position_manager(
            &env,
            &manager,
            &common::types::PositionManagerConfig { is_active: true },
        );
        assert!(crate::storage::add_delegate(
            &env, account_id, &alice, &manager
        ));
        // Pre-transfer: owner and delegate both authorized.
        assert!(is_owner_or_delegate(&env, account_id, &alice, &alice));
        assert!(is_owner_or_delegate(&env, account_id, &manager, &alice));
    });

    position_nft::PositionNftClient::new(&env, &nft).transfer(
        &alice,
        &bob,
        &u32::try_from(account_id).unwrap(),
    );

    env.as_contract(&contract_id, || {
        let owner = crate::storage::account_owner(&env, account_id);
        assert_eq!(owner, bob);
        // Old owner and the grant they made are both dead.
        assert!(!is_owner_or_delegate(&env, account_id, &alice, &owner));
        assert!(!is_owner_or_delegate(&env, account_id, &manager, &owner));
        // New owner works, and a fresh grant by the new owner works.
        assert!(is_owner_or_delegate(&env, account_id, &bob, &owner));
        assert!(crate::storage::add_delegate(
            &env, account_id, &bob, &manager
        ));
        assert!(is_owner_or_delegate(&env, account_id, &manager, &owner));
    });
```

**File:** contracts/controller/src/account.rs (L62-71)
```rust
    let nft = storage::get_position_nft(env);
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
