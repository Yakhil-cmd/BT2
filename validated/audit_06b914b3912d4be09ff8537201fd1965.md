## Analysis

I traced the full execution path of `add_to_delegation_pool` and the downstream accounting machinery.

### Execution Flow

`add_to_delegation_pool` at `src/pool/pool.cairo:221-254`:
1. Asserts staker active, caller is pool_member or reward_address, amount is non-zero
2. Transfers `amount` tokens from caller → pool → staking contract (atomic, via `transfer_to_staking_contract` → `add_stake_from_pool`)
3. Calls `increase_member_balance(pool_member, amount)` which calls `set_member_balance` [1](#0-0) 

### Checkpoint Write Logic

`set_member_balance` writes a checkpoint at `current_epoch + K` (K=2) with:
- `balance = current_balance +

### Citations

**File:** src/pool/pool.cairo (L221-254)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
        }
```
