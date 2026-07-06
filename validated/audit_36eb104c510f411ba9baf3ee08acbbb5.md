### Title
Staker's STRK Principal Permanently Frozen When BTC Pool Token Becomes Irrecoverable — (`src/staking/staking.cairo`)

---

### Summary

A staker who has opened both a STRK pool and a BTC delegation pool will have their entire STRK principal permanently locked if the BTC token contract becomes irrecoverable (e.g., paused, bricked, or otherwise unable to process transfers). The `unstake_action` path unconditionally iterates over **all** pools and attempts a token transfer for each one; a revert in the BTC transfer aborts the whole transaction, leaving the staker's STRK stake frozen with no escape route.

---

### Finding Description

`unstake_action` in `src/staking/staking.cairo` delegates the return of delegated funds to `transfer_to_pools_when_unstake`:

```cairo
// src/staking/staking.cairo  unstake_action  lines 508-511
self.transfer_to_pools_when_unstake(
    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
);
```

`transfer_to_pools_when_unstake` iterates over every pool the staker owns and calls `checked_transfer` on each pool's token:

```cairo
// src/staking/staking.cairo  lines 1661-1682
fn transfer_to_pools_when_unstake(...) {
    for (pool_contract, token_address) in staker_pool_info.pools {
        let pool_balance = self.get_delegated_balance(:staker_address, :pool_contract);
        let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
        let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
        pool_dispatcher.set_staker_removed();
        self.insert_staker_delegated_balance(..., delegated_balance: Zero::zero());
        let decimals = self.get_token_decimals(:token_address);
        token_dispatcher.checked_transfer(          // <-- panics if BTC transfer fails
            recipient: pool_contract,
            amount: pool_balance.to_native_amount(:decimals).into(),
        );
    }
}
```

There is **no active-token guard** here. The `disable_token` function marks a BTC token inactive in `btc_tokens`, but `transfer_to_pools_when_unstake` never consults that flag:

```cairo
// src/staking/staking.cairo  lines 2235-2242
fn is_active_token(self: @ContractState, token_address: ContractAddress, epoch_id: Epoch) -> bool {
    token_address == STRK_TOKEN_ADDRESS
        || is_btc_active(active_status: self.btc_tokens.read(token_address).unwrap(), :epoch_id)
}
```

`is_active_token` is used in reward calculations (e.g., `calculate_staker_pools_rewards` at line 1966) but is **absent** from `transfer_to_pools_when_unstake`. Consequently, even if the security agent calls `disable_token`, the `unstake_action` path still attempts the BTC transfer and reverts. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

A staker who has opened a BTC delegation pool (via `set_open_for_delegation`) and has non-zero BTC delegated balance will be unable to complete `unstake_action` if the BTC token contract becomes permanently non-functional. Because `unstake_intent` already succeeded and removed the staker's own STRK balance from the total stake, the staker's STRK principal is effectively orphaned: it cannot be returned (the action reverts) and it is no longer counted in consensus (the intent already fired). This constitutes **permanent freezing of the staker's principal STRK funds**.

BTC pool members face the same freeze: `exit_delegation_pool_action` in `src/pool/pool.cairo` also calls `token_dispatcher.checked_transfer` at line 330 to return the BTC principal to the member, which would revert identically. [4](#0-3) 

---

### Likelihood Explanation

The protocol is explicitly designed to support BTC as a staking token alongside STRK. BTC-pegged tokens on Starknet (e.g., wBTC bridges) commonly include pausability by a token admin. A pause, a bridge emergency halt, or a contract bug in the BTC token contract is a realistic and non-negligible event. The protocol's own `disable_token` mechanism acknowledges that tokens may need to be deactivated, yet the unstake path does not honour that flag, leaving no administrative escape hatch. [5](#0-4) 

---

### Recommendation

In `transfer_to_pools_when_unstake`, skip the token transfer (and mark the pool balance as zero) when the token is inactive or when the transfer would fail. Alternatively, introduce an emergency-exit path that allows a staker to forfeit their claim on a broken pool's funds and recover only the healthy-token balances. At minimum, ensure `disable_token` causes `transfer_to_pools_when_unstake` to skip the disabled token's transfer so the security agent has an effective mitigation lever.

---

### Proof of Concept

1. Alice stakes STRK and calls `set_open_for_delegation(STRK_TOKEN_ADDRESS)` and `set_open_for_delegation(BTC_TOKEN_ADDRESS)`.
2. Delegators deposit BTC into Alice's BTC pool; `pool_balance > 0` for the BTC pool.
3. The BTC token contract is paused (or otherwise broken), making all `transfer` calls revert.
4. Alice calls `unstake_intent()` — succeeds; her own STRK balance is removed from total stake.
5. Alice waits for `exit_wait_window` to elapse.
6. Alice calls `unstake_action(alice_address)`:
   - `transfer_to_pools_when_unstake` iterates pools.
   - For the STRK pool: `checked_transfer` succeeds.
   - For the BTC pool: `checked_transfer` **panics** because the BTC token is paused.
   - The entire transaction reverts.
7. Alice's STRK principal remains locked in the staking contract with no recovery path. The security agent calling `disable_token(BTC_TOKEN_ADDRESS)` does not help because `transfer_to_pools_when_unstake` does not check `is_active_token`. [6](#0-5) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L483-515)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
```

**File:** src/staking/staking.cairo (L1378-1389)
```text
        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(is_active, "{}", Error::TOKEN_ALREADY_DISABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
            self.emit(TokenManagerEvents::TokenDisabled { token_address });
        }
```

**File:** src/staking/staking.cairo (L1661-1682)
```text
        fn transfer_to_pools_when_unstake(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
        ) {
            for (pool_contract, token_address) in staker_pool_info.pools {
                let pool_balance = self.get_delegated_balance(:staker_address, :pool_contract);
                let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
                let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
                pool_dispatcher.set_staker_removed();
                self
                    .insert_staker_delegated_balance(
                        :staker_address, :pool_contract, delegated_balance: Zero::zero(),
                    );
                let decimals = self.get_token_decimals(:token_address);
                token_dispatcher
                    .checked_transfer(
                        recipient: pool_contract,
                        amount: pool_balance.to_native_amount(:decimals).into(),
                    );
            }
        }
```

**File:** src/staking/staking.cairo (L1965-1968)
```text
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
```

**File:** src/pool/pool.cairo (L328-331)
```text
            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

```
