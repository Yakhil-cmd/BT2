### Title
Missing Epoch Deadline in Staking/Delegation Entry Functions Causes Missed Rewards - (File: src/pool/pool.cairo, src/staking/staking.cairo)

### Summary
The `enter_delegation_pool`, `add_to_delegation_pool`, `stake`, and `increase_stake` functions all record balance changes at `current_epoch + K` (computed at execution time). If a user's transaction is submitted near the end of epoch N but included in epoch N+1 due to sequencer delay or gas fluctuation, the activation epoch silently shifts from `N+K` to `N+1+K`, causing the user to forfeit one full epoch of yield with no recourse.

### Finding Description

Every balance-modifying entry function ultimately calls either `set_member_balance` (pool) or `insert_staker_own_balance` / `insert_staker_delegated_balance` (staking), all of which key the trace entry on `get_epoch_plus_k()`:

**Pool contract** — `set_member_balance`: [1](#0-0) 

`get_epoch_plus_k` in the pool: [2](#0-1) 

**Staking contract** — `insert_staker_own_balance`: [3](#0-2) 

`get_epoch_plus_k` in the staking contract: [4](#0-3) 

`K = 2` is the constant delay: [5](#0-4) 

None of these functions accept a `latest_epoch` or deadline parameter. The activation epoch is determined entirely by `get_block_number()` at inclusion time, not at submission time.

### Impact Explanation

A user who submits `enter_delegation_pool` or `stake` at the last block of epoch N expects their balance to become active at epoch N+2 (K=2). If the transaction is included one block later (first block of epoch N+1), the balance activates at epoch N+3 instead. The user earns zero rewards for epoch N+2 — one full epoch of yield is permanently lost. For large delegators or stakers, one epoch of missed rewards is a material loss. This maps to **High: Theft of unclaimed yield**.

### Likelihood Explanation

Starknet epochs are block-based. With a configurable epoch length (e.g., 40 blocks), any transaction submitted within the last block of an epoch is at risk. Gas price spikes, sequencer reordering, or simple network latency can push a transaction across the boundary. This is a constant probabilistic risk that grows with the number of stakers and delegators. No user action can prevent it once the transaction is submitted.

### Recommendation

Add a `latest_epoch` deadline parameter to `enter_delegation_pool`, `add_to_delegation_pool`, `stake`, and `increase_stake`. At the start of each function, assert:

```cairo
assert!(self.get_current_epoch() <= latest_epoch, "Transaction epoch deadline exceeded");
```

This allows users to express their intent precisely and have the transaction revert harmlessly if it lands in a later epoch.

### Proof of Concept

1. Epoch length = 40 blocks. Current block = 39 (last block of epoch N).
2. User calls `enter_delegation_pool(reward_address, amount=1_000_000_STRK)`.
3. Transaction is included at block 40 (first block of epoch N+1) due to sequencer delay.
4. `get_current_epoch()` returns N+1; `get_epoch_plus_k()` returns N+3.
5. `set_member_balance` inserts the balance at key N+3 instead of N+2.
6. `get_balance_at_current_epoch` returns 0 for epoch N+2 — the user earns no rewards for that epoch.
7. The user has no way to cancel or re-submit; the loss is permanent.

The same path applies to `stake` via `initialize_staker_own_balance_trace` → `insert_staker_own_balance` → `get_epoch_plus_k`. [6](#0-5) [7](#0-6)

### Citations

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

**File:** src/pool/pool.cairo (L699-701)
```text
        fn get_epoch_plus_k(self: @ContractState) -> Epoch {
            self.get_current_epoch() + K.into()
        }
```

**File:** src/pool/pool.cairo (L718-729)
```text
        fn set_member_balance(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) {
            let trace = self.pool_member_epoch_balance.entry(pool_member);
            // `cumulative_rewards_trace_idx` should be set to
            // `self.cumulative_rewards_trace_length() + (K - 1)`.
            let pool_member_balance = PoolMemberBalanceTrait::new(
                balance: amount,
                cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
            );
            trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
        }
```

**File:** src/staking/staking.cairo (L2004-2006)
```text
        fn get_epoch_plus_k(self: @ContractState) -> Epoch {
            self.get_current_epoch() + K.into()
        }
```

**File:** src/staking/staking.cairo (L2008-2015)
```text
        fn insert_staker_own_balance(
            ref self: ContractState, staker_address: ContractAddress, own_balance: NormalizedAmount,
        ) {
            self
                .staker_own_balance_trace
                .entry(staker_address)
                .insert(key: self.get_epoch_plus_k(), value: own_balance.to_strk_native_amount());
        }
```

**File:** src/staking/staking.cairo (L2017-2031)
```text
        fn initialize_staker_own_balance_trace(
            ref self: ContractState, staker_address: ContractAddress, own_balance: NormalizedAmount,
        ) {
            assert!(
                self.staker_own_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED,
            );
            // Initialize trace with baseline entry to ensure robust balance queries.
            self
                .staker_own_balance_trace
                .entry(staker_address)
                .insert(key: STARTING_EPOCH, value: Zero::zero());
            self.insert_staker_own_balance(:staker_address, :own_balance);
        }
```

**File:** src/constants.cairo (L12-13)
```text
/// Epoch delay before consensus-related changes (e.g. balances, token activations) take effect.
pub(crate) const K: u8 = 2;
```
