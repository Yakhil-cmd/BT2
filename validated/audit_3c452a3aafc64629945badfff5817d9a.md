### Title
Staker's STRK permanently frozen when BTC pool token contract malfunctions — (`src/staking/staking.cairo`)

---

### Summary

The `transfer_to_pools_when_unstake` internal function, called unconditionally from `unstake_action`, loops over every pool a staker owns and performs an external token transfer for each one. If a BTC token contract becomes broken or paused, the transfer reverts, causing `unstake_action` to revert entirely. Because there is no mechanism to skip a broken pool and no way to cancel an `unstake_intent`, the staker's STRK is permanently frozen inside the staking contract.

---

### Finding Description

`unstake_action` calls `transfer_to_pools_when_unstake` to settle all pool balances before returning the staker's own STRK: [1](#0-0) 

```cairo
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
        ...
        token_dispatcher
            .checked_transfer(
                recipient: pool_contract,
                amount: pool_balance.to_native_amount(:decimals).into(),
            );
    }
}
```

The loop iterates over **all** pools — both STRK and BTC — with no conditional skip. For a BTC pool, `token_dispatcher.checked_transfer` calls the external BTC token contract. If that contract is paused, frozen, or otherwise broken, the call reverts and the entire `unstake_action` transaction reverts. [2](#0-1) 

The protocol does expose a `disable_token` function callable by the security agent: [3](#0-2) 

However, `disable_token` only marks the token inactive in `btc_tokens` storage. It does **not** remove the pool from the staker's pool list, and `transfer_to_pools_when_unstake` performs no `is_active_token` check before transferring. Disabling the token therefore provides no relief to a staker already holding a BTC pool.

After `unstake_intent` is called, the staker's stake is removed from the total stake and `unstake_time` is set: [4](#0-3) 

There is no `cancel_unstake_intent` function in the contract. The staker is therefore locked in a limbo state: their STRK sits in the staking contract, `unstake_intent` has already been recorded, and `unstake_action` cannot complete.

---

### Impact Explanation

**High — Permanent freezing of staker funds.**

Once `unstake_intent` is called, the staker's own STRK balance is removed from the total stake trace and the staker cannot call any other state-changing function (all require `unstake_time.is_none()`). If `unstake_action` is permanently blocked by a broken BTC token, the staker's STRK is irrecoverably locked in the staking contract with no administrative escape hatch.

---

### Likelihood Explanation

BTC tokens are external ERC20 contracts added by the token admin via `add_token`. Wrapped BTC tokens (e.g., wBTC, tBTC) commonly include admin-controlled pause mechanisms. A pause, exploit, or regulatory freeze of the underlying token contract is a realistic operational risk. The protocol's own `disable_token` function implicitly acknowledges this risk but fails to protect stakers already in the exit flow.

---

### Recommendation

1. **Skip zero-balance or inactive-token pools** in `transfer_to_pools_when_unstake`: if `pool_balance` is zero or the token is disabled, skip the transfer (and still call `set_staker_removed` so the pool is properly marked).
2. **Add a `cancel_unstake_intent` function** so a staker can return to an active state if `unstake_action` is blocked.
3. **Ensure `disable_token` triggers a forced settlement** of any pending exit intents for that token, transferring the staker's BTC pool balance to the pool contract at the time of disabling.

---

### Proof of Concept

1. Staker calls `set_open_for_delegation(btc_token_address)` — a BTC pool is deployed and linked to the staker.
2. The BTC token contract is paused by its admin (or exploited).
3. Staker calls `unstake_intent()` — succeeds; no token transfers occur; `unstake_time` is set; staker's stake is removed from total stake.
4. Staker waits for `exit_wait_window` to elapse.
5. Staker calls `unstake_action(staker_address)`.
6. Inside `unstake_action`, `transfer_to_pools_when_unstake` is reached; it iterates to the BTC pool and calls `token_dispatcher.checked_transfer(recipient: btc_pool, amount: btc_balance)`.
7. The paused BTC token reverts — `unstake_action` reverts entirely.
8. The staker's STRK remains locked in the staking contract. There is no cancel path. Funds are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L433-481)
```text
        fn unstake_intent(ref self: ContractState) -> Timestamp {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            // Set the unstake time.
            let unstake_time = Time::now().add(delta: self.exit_wait_window.read());
            staker_info.unstake_time = Option::Some(unstake_time);
            self.write_staker_info(:staker_address, :staker_info);

            // Write the unstake intent epoch.
            self.staker_unstake_intent_epoch.write(staker_address, self.get_epoch_plus_k());

            // Write off the delegated stake from the total stake.
            for (pool_contract, token_address) in self
                .staker_pool_info
                .entry(staker_address)
                .pools {
                let amount = self.get_delegated_balance(:staker_address, :pool_contract);
                self.remove_from_total_stake(:token_address, :amount);
                let decimals = self.get_token_decimals(:token_address);
                self
                    .emit(
                        Events::StakeDelegatedBalanceChanged {
                            staker_address,
                            token_address,
                            old_delegated_stake: amount.to_native_amount(:decimals),
                            new_delegated_stake: Zero::zero(),
                        },
                    );
            }
            // Write off the self stake from the total stake.
            let old_self_stake = self.get_own_balance(:staker_address);
            self.remove_from_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: old_self_stake);

            // Emit events.
            self.emit(Events::StakerExitIntent { staker_address, exit_timestamp: unstake_time });
            self
                .emit(
                    Events::StakeOwnBalanceChanged {
                        staker_address,
                        old_self_stake: old_self_stake.to_strk_native_amount(),
                        new_self_stake: Zero::zero(),
                    },
                );
            unstake_time
        }
```

**File:** src/staking/staking.cairo (L483-514)
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
