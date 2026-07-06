### Title
Delegation Pool Creatable for Disabled Token, Locking Delegator Funds Without Yield - (File: src/staking/staking.cairo)

### Summary
`set_open_for_delegation` validates only that a token *exists* in the registry (`does_token_exist`) but never checks whether the token is currently *active* (`is_active_token`). A staker can therefore open a delegation pool for a disabled BTC token. Delegators who enter that pool have their funds locked in the staking contract for the full exit-wait window (up to 12 weeks) while earning zero rewards, because reward distribution explicitly skips inactive tokens.

### Finding Description
`set_open_for_delegation` (staking.cairo line 551) gates pool creation on `does_token_exist`:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
``` [1](#0-0) 

`does_token_exist` is a pure registry check (is the address STRK or present in `btc_tokens`?). It is deliberately separate from `is_active_token`, as evidenced by `get_total_stake_for_token`, which requires **both** checks:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
assert!(
    self.is_active_token(:token_address, epoch_id: curr_epoch),
    "{}",
    Error::TOKEN_NOT_ACTIVE,
);
``` [2](#0-1) 

`disable_token` (called by the security agent) sets the token inactive starting at `current_epoch + K`:

```cairo
let next_is_active_first_epoch = self.get_epoch_plus_k();
self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
``` [3](#0-2) 

After disabling, a staker can still call `set_open_for_delegation` with the disabled token address and successfully deploy a new pool contract. Delegators who then call `enter_delegation_pool` on that pool have their tokens transferred to the staking contract via `add_stake_from_pool`, which performs no token-activity check: [4](#0-3) 

Reward distribution in `calculate_staker_pools_rewards` explicitly skips inactive tokens:

```cairo
if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
    continue;
}
``` [5](#0-4) 

So delegators' principal is held in the staking contract, earns nothing, and can only be recovered after the exit-wait window (default one week, maximum twelve weeks). [6](#0-5) 

### Impact Explanation
Delegators who join a pool backed by a disabled token:
- Receive **zero yield** for the entire lock period.
- Cannot recover principal until the exit-wait window expires (up to `MAX_EXIT_WAIT_WINDOW` = 12 weeks).

This constitutes **temporary freezing of funds** and loss of unclaimed yield — matching the Medium/High impact tiers in the allowed scope (griefing with damage to users; temporary freezing of funds).

### Likelihood Explanation
- A registered staker (unprivileged) can call `set_open_for_delegation` at any time with no special role.
- A token can be disabled by the security agent at any point; the window between disabling and the staker creating a pool is unbounded.
- Delegators relying on on-chain pool listings (e.g., via `NewDelegationPool` events) have no in-protocol signal that the underlying token is inactive.
- The staker need not profit; the attack is pure griefing.

### Recommendation
Add an `is_active_token` guard inside `set_open_for_delegation`, mirroring the pattern already used in `get_total_stake_for_token`:

```cairo
assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
assert!(
    self.is_active_token(:token_address, epoch_id: self.get_current_epoch()),
    "{}",
    Error::TOKEN_NOT_ACTIVE,
);
```

This ensures pools can only be created for tokens that are currently active, preventing delegators from being lured into yield-less positions.

### Proof of Concept
1. Security agent calls `disable_token(btc_token)` → token is inactive from epoch `E+K`.
2. Malicious staker (already registered) calls `set_open_for_delegation(btc_token)` → succeeds because `does_token_exist` returns `true`; a new pool contract is deployed.
3. Victim delegator calls `pool.enter_delegation_pool(reward_addr, amount)` → `assert_staker_is_active()` passes (staker not removed), `add_stake_from_pool` passes (no activity check), funds locked in staking contract.
4. Reward distribution via `calculate_staker_pools_rewards` skips the disabled token → delegator earns zero rewards.
5. Delegator calls `exit_delegation_pool_intent` then must wait the full exit-wait window before recovering principal via `exit_delegation_pool_action`. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
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

**File:** src/staking/staking.cairo (L824-830)
```text
            assert!(self.does_token_exist(:token_address), "{}", Error::INVALID_TOKEN_ADDRESS);
            assert!(
                self.is_active_token(:token_address, epoch_id: curr_epoch),
                "{}",
                Error::TOKEN_NOT_ACTIVE,
            );
            let decimals = self.get_token_decimals(:token_address);
```

**File:** src/staking/staking.cairo (L1003-1015)
```text
        fn add_stake_from_pool(
            ref self: ContractState, staker_address: ContractAddress, amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let pool_contract = get_caller_address();
            let token_address = self
                .staker_pool_info
                .entry(staker_address)
                .get_pool_token(:pool_contract)
                .expect_with_err(Error::CALLER_IS_NOT_POOL_CONTRACT);
```

**File:** src/staking/staking.cairo (L1386-1388)
```text
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
            self.emit(TokenManagerEvents::TokenDisabled { token_address });
```

**File:** src/staking/staking.cairo (L1966-1968)
```text
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
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
