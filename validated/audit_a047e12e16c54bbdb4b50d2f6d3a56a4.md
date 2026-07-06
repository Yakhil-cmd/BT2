### Title
Zero-Amount Token Transfer in `transfer_to_pools_when_unstake` Can Permanently Freeze Staker Funds - (File: src/staking/staking.cairo)

### Summary

When a staker calls `unstake_action`, the internal function `transfer_to_pools_when_unstake` iterates over all of the staker's delegation pools and transfers each pool's current delegated balance back to the pool contract. If a pool's delegated balance is zero (because all delegators have already exited), a zero-amount transfer is attempted on the pool's token. For BTC-variant tokens that revert on zero-value transfers, this causes `unstake_action` to revert, permanently freezing the staker's own STRK stake inside the staking contract.

### Finding Description

`unstake_action` in `src/staking/staking.cairo` calls `transfer_to_pools_when_unstake`, which iterates over every pool associated with the staker and unconditionally calls `checked_transfer` with the pool's current delegated balance:

```cairo
// src/staking/staking.cairo ~line 1666-1680
for (pool_contract, token_address) in staker_pool_info.pools {
    let pool_balance = self.get_delegated_balance(:staker_address, :pool_contract);
    let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
    pool_dispatcher.set_staker_removed();
    self.insert_staker_delegated_balance(
        :staker_address, :pool_contract, delegated_balance: Zero::zero(),
    );
    let decimals = self.get_token_decimals(:token_address);
    token_dispatcher.checked_transfer(
        recipient: pool_contract,
        amount: pool_balance.to_native_amount(:decimals).into(),
    );
}
```

There is no guard against `pool_balance` being zero before the transfer is issued. The protocol supports non-STRK tokens (e.g., BTC variants) via `IStakingTokenManager::add_token`. If the BTC token deployed for a pool reverts on zero-value transfers — a well-documented class of ERC-20 tokens — and all delegators have already exited that pool (reducing `pool_balance` to zero in the staking contract), then `unstake_action` will revert every time it is called, with no alternative exit path for the staker. [1](#0-0) 

The staker's own STRK balance and accrued rewards are only returned inside `unstake_action`; there is no other function that allows a staker to recover their principal. [2](#0-1) 

The pool's delegated balance reaches zero legitimately when all pool members call `exit_delegation_pool_intent` followed by `exit_delegation_pool_action`, which routes through `remove_from_delegation_pool_action` and clears the staking contract's internal delegated balance for that pool. [3](#0-2) 

### Impact Explanation

A staker who opened a BTC delegation pool, whose pool balance has dropped to zero (all delegators exited), cannot call `unstake_action` if the BTC token reverts on zero-value transfers. The staker's own STRK principal and all unclaimed STRK rewards are locked inside the staking contract with no alternative exit path. This constitutes **permanent freezing of funds** (High severity) or at minimum **temporary freezing of funds** (High severity) until an external party re-delegates to the pool to make the balance non-zero.

### Likelihood Explanation

The protocol explicitly supports adding non-STRK tokens via `add_token` (governed by `token_admin`). The scenario where all delegators exit a BTC pool before the staker exits is a normal operational sequence — delegators are free to exit independently. The class of ERC-20 tokens that revert on zero-value transfers is well-documented and not exotic. No malicious actor is required; the freeze occurs through normal user behavior combined with a token that has this property. [4](#0-3) 

### Recommendation

Add a zero-amount guard before each `checked_transfer` call in `transfer_to_pools_when_unstake`:

```cairo
let native_amount = pool_balance.to_native_amount(:decimals);
if native_amount.is_non_zero() {
    token_dispatcher.checked_transfer(
        recipient: pool_contract,
        amount: native_amount.into(),
    );
}
```

This mirrors the existing pattern already used in `remove_from_delegation_pool_action` (line 1119: `if undelegate_intent.amount.is_zero() { return; }`), which already guards against zero-amount transfers in a related code path. [5](#0-4) 

### Proof of Concept

1. Token admin adds a BTC token that reverts on zero-value transfers via `add_token`.
2. Staker calls `stake(pool_enabled: false)` then `set_open_for_delegation(token_address: btc_token)`, opening a BTC pool.
3. One or more delegators call `enter_delegation_pool` on the BTC pool.
4. All delegators call `exit_delegation_pool_intent` then `exit_delegation_pool_action`. After this, `get_delegated_balance(staker_address, btc_pool_contract)` returns `0`.
5. Staker calls `unstake_intent`, then waits for `exit_wait_window`.
6. Staker calls `unstake_action`. Inside `transfer_to_pools_when_unstake`, `pool_balance` is `0` for the BTC pool. `checked_transfer(recipient: btc_pool_contract, amount: 0)` is called on the BTC token, which reverts.
7. `unstake_action` reverts. The staker's STRK principal and rewards remain locked with no recovery path. [6](#0-5)

### Citations

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

**File:** src/staking/staking.cairo (L1113-1146)
```text
        fn remove_from_delegation_pool_action(ref self: ContractState, identifier: felt252) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let pool_contract = get_caller_address();
            let undelegate_intent_key = UndelegateIntentKey { pool_contract, identifier };
            let undelegate_intent = self.get_pool_exit_intent(:undelegate_intent_key);
            if undelegate_intent.amount.is_zero() {
                return;
            }
            assert!(
                Time::now() >= undelegate_intent.unpool_time,
                "{}",
                GenericError::INTENT_WINDOW_NOT_FINISHED,
            );

            // Clear the intent.
            self.clear_undelegate_intent(:undelegate_intent_key);
            // Extract the token address of the pool contract.
            let token_address = get_undelegate_intent_token(:undelegate_intent);
            let decimals = self.get_token_decimals(:token_address);
            // Transfer the intent amount to the pool contract.
            let native_amount = undelegate_intent.amount.to_native_amount(:decimals);
            let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
            token_dispatcher
                .checked_transfer(recipient: pool_contract, amount: native_amount.into());

            // Emit event.
            self
                .emit(
                    Events::RemoveFromDelegationPoolAction {
                        pool_contract, token_address, identifier, amount: native_amount,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1343-1360)
```text
    impl StakingTokenManagerImpl of IStakingTokenManager<ContractState> {
        fn add_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_token_admin();
            assert!(token_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
            assert!(self.staker_info.read(token_address).is_none(), "{}", Error::TOKEN_IS_STAKER);
            assert!(token_address != STRK_TOKEN_ADDRESS, "{}", Error::INVALID_TOKEN_ADDRESS);
            assert!(
                self.btc_tokens.read(token_address).is_none(), "{}", Error::TOKEN_ALREADY_EXISTS,
            );
            let token_dispatcher = IERC20MetadataDispatcher { contract_address: token_address };
            let decimals = token_dispatcher.decimals();
            assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
            self.btc_tokens.write(token_address, (STARTING_EPOCH, false));
            self.token_decimals.write(token_address, decimals);
            // Initialize the token total stake trace.
            self
                .tokens_total_stake_trace
                .entry(token_address)
```

**File:** src/staking/staking.cairo (L1661-1681)
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
```
