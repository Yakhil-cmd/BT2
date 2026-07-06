### Title
Missing Active-Token Check in `set_open_for_delegation` Allows Pool Creation for Disabled Tokens — (File: `src/staking/staking.cairo`)

### Summary
`set_open_for_delegation` validates that a token *exists* but never validates that the token is *active*. A staker can deploy a delegation pool for a BTC token that has been disabled by the security agent, allowing delegators to lock funds in a pool that earns zero staking rewards.

### Finding Description
The `Staking` contract maintains a per-token active/inactive flag in `btc_tokens: IterableMap<ContractAddress, (Epoch, bool)>`. The `bool` field (`is_active`) is toggled by privileged calls to `enable_token` / `disable_token`. The protocol enforces this flag in read-only paths: `get_total_stake_for_token` asserts both `does_token_exist` **and** `is_active_token` before returning data. [1](#0-0) 

However, `set_open_for_delegation` only asserts `does_token_exist` and never calls `is_active_token`: [2](#0-1) 

The storage comment makes the intent of the flag explicit: [3](#0-2) 

Once a pool is deployed for a disabled token, `enter_delegation_pool` in the pool contract performs no active-token check either — it only checks `assert_staker_is_active()` (i.e., `!staker_removed`): [4](#0-3) 

### Impact Explanation
Delegators who enter a pool backed by a disabled token:
1. Transfer real BTC to the staking contract.
2. Earn **zero staking rewards** because the disabled token contributes zero staking power to the epoch calculation.
3. Cannot recover funds immediately — they must submit `exit_delegation_pool_intent` and wait the full `exit_wait_window` (default 1 week, up to 12 weeks) before calling `exit_delegation_pool_action`.

This constitutes **temporary freezing of funds** and **theft of unclaimed yield** for the duration of the exit window — both are listed in the allowed impact scope.

### Likelihood Explanation
The security agent disables a token precisely to halt its use (e.g., in response to a discovered vulnerability or oracle manipulation). A staker — acting either maliciously or simply before migrating — can call `set_open_for_delegation` with the disabled token address at any time. Any delegator who subsequently joins the pool (e.g., attracted by the staker's reputation) suffers the impact. No privileged access is required beyond being a registered staker.

### Recommendation
Add an `is_active_token` assertion inside `set_open_for_delegation`, mirroring the pattern already used in `get_total_stake_for_token`:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
let curr_epoch = self.get_current_epoch();
assert!(
    self.is_active_token(:token_address, epoch_id: curr_epoch),
    "{}",
    Error::TOKEN_NOT_ACTIVE,
);
```

### Proof of Concept
1. Security agent calls `disable_token(btc_token_address)` — `is_active` is set to `false`.
2. Staker calls `set_open_for_delegation(btc_token_address)` — passes because only `does_token_exist` is checked; a pool contract is deployed.
3. Delegator calls `pool.enter_delegation_pool(reward_addr, amount)` — passes because the pool only checks `!staker_removed`.
4. Delegator's BTC is now locked in the staking contract. The disabled token contributes zero staking power, so the delegator earns no rewards.
5. Delegator must call `exit_delegation_pool_intent` and wait `exit_wait_window` (≥ 1 week) before recovering funds via `exit_delegation_pool_action`. [2](#0-1) [4](#0-3) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L160-166)
```text
        /// Map token address to (is_active_first_epoch, is_active).
        /// The `is_active_first_epoch` is the first epoch that the `token_address` is in
        /// `is_active` state.
        /// Namely, if `e >= is_active_first_epoch` then the token is in `is_active` state.
        /// If `current_epoch <= e < is_active_first_epoch`, the tokens is in `!is_active` state.
        /// The state of older epochs cannot be determined.
        btc_tokens: IterableMap<ContractAddress, (Epoch, bool)>,
```

**File:** src/staking/staking.cairo (L542-572)
```text
        fn set_open_for_delegation(
            ref self: ContractState, token_address: ContractAddress,
        ) -> ContractAddress {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
            assert!(
                !staker_pool_info.has_pool_for_token(:token_address),
                "{}",
                Error::STAKER_ALREADY_HAS_POOL,
            );
            let commission = staker_pool_info.commission();

            // Deploy delegation pool contract.
            let pool_contract = self
                .deploy_delegation_pool_from_staking_contract(
                    :staker_address,
                    staking_contract: get_contract_address(),
                    :token_address,
                    :commission,
                );
            // Update pool to storage.
            staker_pool_info.pools.write(pool_contract, token_address);
            // Initialize the delegated balance trace.
            self.initialize_staker_delegated_balance_trace(:staker_address, :pool_contract);
            pool_contract
        }
```

**File:** src/staking/staking.cairo (L820-832)
```text
        fn get_total_stake_for_token(
            self: @ContractState, token_address: ContractAddress,
        ) -> Amount {
            let curr_epoch = self.get_current_epoch();
            assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
            assert!(
                self.is_active_token(:token_address, epoch_id: curr_epoch),
                "{}",
                Error::TOKEN_NOT_ACTIVE,
            );
            let decimals = self.get_token_decimals(:token_address);
            self._get_total_stake(:token_address).to_native_amount(:decimals)
        }
```

**File:** src/pool/pool.cairo (L182-219)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
```
