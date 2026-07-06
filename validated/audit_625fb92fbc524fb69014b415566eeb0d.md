### Title
Staker Can Open Delegation Pool for Disabled Token, Causing Delegators to Lose Yield - (File: src/staking/staking.cairo)

### Summary
`set_open_for_delegation` validates only that a token exists (`does_token_exist`) but never checks whether the token is currently active (`is_active_token`). After a token is disabled by the security agent, any staker who does not yet have a pool for that token can still open one, attracting delegators whose stake will earn zero rewards and contribute zero staking power.

### Finding Description
The `IStakingTokenManager` interface exposes `disable_token`, which marks a BTC-class token as inactive with a K-epoch delay. The intent is that disabled tokens "are not eligible for rewards and have no staking power." [1](#0-0) 

When a staker calls `set_open_for_delegation`, the only token-related guard is:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
``` [2](#0-1) 

`does_token_exist` checks only that the token is present in the `btc_tokens` iterable map — i.e., that it was ever added — not that it is currently active. The contract already has a separate `is_active_token` predicate, which is used in `get_total_stake_for_token` alongside `does_token_exist`:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
assert!(
    self.is_active_token(:token_address, epoch_id: curr_epoch),
    "{}",
    Error::TOKEN_NOT_ACTIVE,
);
``` [3](#0-2) 

`set_open_for_delegation` applies only the first of these two checks, leaving the second entirely absent. A newly added but never-enabled token also passes `does_token_exist` (it is written with `is_active = false` at `add_token` time), so the gap covers both the "added but never enabled" and the "previously enabled, now disabled" states. [4](#0-3) 

### Impact Explanation
Delegators who `enter_delegation_pool` or `add_to_delegation_pool` on a pool backed by a disabled token receive zero rewards for every epoch they remain delegated, because the disabled token contributes neither staking power nor reward entitlement. The yield they would have earned in a valid pool is permanently lost for those epochs. This matches **High: Theft of unclaimed yield / Permanent freezing of unclaimed yield**, or at minimum **Medium: Griefing with damage to users**.

### Likelihood Explanation
The precondition is that a token has been disabled by the security agent (a realistic operational event, e.g., a BTC token found to be problematic). After that, any staker who does not yet hold a pool for that token — an unprivileged, permissionless actor — can call `set_open_for_delegation` with the disabled token address. No special access is required beyond being a registered staker. Delegators who then join the pool suffer the yield loss.

### Recommendation
Add an `is_active_token` check inside `set_open_for_delegation`, mirroring the pattern already used in `get_total_stake_for_token`:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
// Add:
assert!(
    self.is_active_token(:token_address, epoch_id: self.get_current_epoch()),
    "{}",
    Error::TOKEN_NOT_ACTIVE,
);
``` [5](#0-4) 

### Proof of Concept

1. Token admin calls `add_token(btc_address)` → token stored with `is_active = false`.
2. Token admin calls `enable_token(btc_address)` → token becomes active after K epochs.
3. Security agent calls `disable_token(btc_address)` → token becomes inactive after K epochs (e.g., due to a discovered issue).
4. Staker (who has no BTC pool yet) calls `set_open_for_delegation(btc_address)`.
   - `does_token_exist(btc_address)` → **passes** (token is in `btc_tokens` map).
   - `is_active_token` is **never checked** → pool is deployed successfully.
5. Delegators call `enter_delegation_pool` on the new pool, locking BTC.
6. Every epoch, the disabled token contributes zero staking power and zero rewards. Delegators permanently lose the yield they would have earned in a valid pool. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/interface.cairo (L279-282)
```text
    ///
    /// **Note**: disabled token is not eligible for rewards and has no staking power but still can
    /// be staked or unstaked.
    fn disable_token(ref self: TContractState, token_address: ContractAddress);
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

**File:** src/staking/staking.cairo (L824-829)
```text
            assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
            assert!(
                self.is_active_token(:token_address, epoch_id: curr_epoch),
                "{}",
                Error::TOKEN_NOT_ACTIVE,
            );
```

**File:** src/staking/staking.cairo (L1355-1355)
```text
            self.btc_tokens.write(token_address, (STARTING_EPOCH, false));
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
