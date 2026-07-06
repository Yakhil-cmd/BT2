### Title
Missing Zero-Address Check on `reward_address` Allows Permanent Freezing of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
The `stake()` and `change_reward_address()` functions in `staking.cairo`, and `enter_delegation_pool()` and `change_reward_address()` in `pool.cairo`, accept a user-supplied `reward_address` without checking that it is non-zero. If a staker or pool member sets their `reward_address` to the zero address, all accrued STRK rewards will be transferred to address `0` and permanently lost.

### Finding Description
In `staking.cairo`, the `stake()` function performs several sanity checks on its inputs — it verifies the staker does not already exist, the operational address is not in use, the staker address is not a token address, the reward address is not a token address, and the amount meets the minimum — but it never asserts `reward_address.is_non_zero()`. [1](#0-0) 

Similarly, `change_reward_address()` in `staking.cairo` only checks that the new address is not a registered token address, with no zero-address guard: [2](#0-1) 

The same pattern exists in `pool.cairo`. `enter_delegation_pool()` checks `REWARD_ADDRESS_IS_TOKEN` but not zero: [3](#0-2) 

And `change_reward_address()` in the pool contract has the same omission: [4](#0-3) 

When `claim_rewards()` is subsequently called, the staking contract reads `staker_info.reward_address` and transfers all accumulated STRK rewards to it. If that address is zero, the tokens are irrecoverably burned: [5](#0-4) 

The same transfer-to-reward-address path exists in the pool's `claim_rewards()`, which sends STRK to `pool_member_info.reward_address`: [6](#0-5) 

The codebase already defines a `ZERO_ADDRESS` error and uses it in other contexts, confirming the intent to guard against zero addresses — but this guard is absent from the reward-address input paths: [7](#0-6) 

### Impact Explanation
Any staker who calls `stake(reward_address: 0, ...)` or later calls `change_reward_address(reward_address: 0)` will have all future STRK reward claims sent to address `0`. The tokens are unrecoverable. The same applies to pool members via `enter_delegation_pool(reward_address: 0, ...)` or `change_reward_address(reward_address: 0)`. This constitutes **permanent freezing of unclaimed yield**, which is a High-severity impact under the allowed scope.

### Likelihood Explanation
The entry points are callable by any unprivileged staker or delegator with no special role required. A user who mistakenly passes a zero address (e.g., from an uninitialized variable in a script or front-end bug) will silently register it. There is no on-chain revert to warn them. The existing `REWARD_ADDRESS_IS_TOKEN` check demonstrates the protocol already validates this field for other invalid values, making the omission of a zero check a realistic oversight.

### Recommendation
Add `reward_address.is_non_zero()` assertions in all four locations:

1. `stake()` in `staking.cairo` — after the existing token-address check.
2. `change_reward_address()` in `staking.cairo` — alongside the existing `REWARD_ADDRESS_IS_TOKEN` check.
3. `enter_delegation_pool()` in `pool.cairo` — after the existing token-address check.
4. `change_reward_address()` in `pool.cairo` — alongside the existing `REWARD_ADDRESS_IS_TOKEN` check.

Use the already-defined `GenericError::ZERO_ADDRESS` error for consistency with the rest of the codebase.

### Proof of Concept

1. Deploy the staking system normally.
2. Call `stake(reward_address: 0, operational_address: <valid>, amount: <min_stake>)` from any address with sufficient STRK balance and approval.
3. The call succeeds — no revert occurs because the only reward-address check (`REWARD_ADDRESS_IS_TOKEN`) passes for address `0`.
4. Advance epochs and perform attestations so rewards accrue.
5. Call `claim_rewards(staker_address: <staker>)`.
6. The contract reads `reward_address = 0` from storage and executes `checked_transfer(recipient: 0, amount: rewards)`.
7. All accrued STRK rewards are transferred to the zero address and permanently lost.

The same sequence applies to a pool member calling `enter_delegation_pool(reward_address: 0, amount: <amount>)` followed by `claim_rewards(pool_member: <member>)`.

### Citations

**File:** src/staking/staking.cairo (L288-317)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L411-431)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
        }
```

**File:** src/staking/staking.cairo (L517-531)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let old_address = staker_info.reward_address;

            // Update reward_address and commit to storage.
            staker_info.reward_address = reward_address;
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/pool/pool.cairo (L182-206)
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
```

**File:** src/pool/pool.cairo (L361-377)
```text
            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
```

**File:** src/pool/pool.cairo (L505-517)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_address = pool_member_info.reward_address;

            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);
```

**File:** src/errors.cairo (L20-20)
```text
    ZERO_ADDRESS,
```
