Based on my analysis of the codebase, I found a valid analog to the zero-address validation vulnerability class.

---

### Title
Missing Zero Address Validation for `reward_address` Causes Permanent Freezing of Unclaimed Yield — (`src/pool/pool.cairo`)

### Summary
The `enter_delegation_pool()` function in `pool.cairo` accepts a caller-supplied `reward_address` without validating it against the zero address. If a pool member passes `reward_address = 0`, all future reward claims are silently transferred to address zero, permanently destroying the member's unclaimed yield.

### Finding Description
In `pool.cairo`, `enter_delegation_pool()` accepts `reward_address` from the caller and stores it directly in the pool member record without a zero-address check: [1](#0-0) 

The only address-related validation performed is that `reward_address` is not a token contract address: [2](#0-1) 

There is no `assert!(!reward_address.is_zero(), ...)` guard. The stored `reward_address` is later used as the direct recipient in `claim_rewards`: [3](#0-2) 

Rewards are unconditionally transferred to `reward_address` with no post-storage zero check. The same pattern exists in `staking.cairo`'s `stake()` function, which also accepts `reward_address` without a zero check and stores it for use in `claim_rewards`: [4](#0-3) [5](#0-4) 

### Impact Explanation
If `reward_address` is set to zero at entry time, every subsequent `claim_rewards` call silently transfers accumulated STRK rewards to address zero. On Starknet, address zero is uncontrolled; tokens sent there are irrecoverable. This constitutes **permanent freezing of unclaimed yield** for the affected pool member or staker. There is no recovery path once the address is committed to storage.

### Likelihood Explanation
Any unprivileged pool member or staker can trigger this by passing `ContractAddress::zero()` as `reward_address`. This can occur through a scripting error, a misconfigured deployment script, or a front-end bug. The call requires no special privileges — it is a standard public entry point reachable by any user.

### Recommendation
Add an explicit zero-address assertion in both `enter_delegation_pool()` and `stake()` before storing `reward_address`:

```cairo
assert!(!reward_address.is_zero(), "{}", GenericError::REWARD_ADDRESS_IS_ZERO);
```

Apply the same guard to `change_reward_address` in both contracts to prevent post-registration misconfiguration.

### Proof of Concept

1. Pool member calls `pool.enter_delegation_pool(reward_address: ContractAddress::zero(), amount: valid_amount)`.
2. No zero-address check exists at lines 182–206 of `pool.cairo`; the call succeeds and `reward_address = 0` is written to storage.
3. The pool member accumulates STRK rewards over subsequent epochs.
4. Anyone calls `pool.claim_rewards(pool_member: victim_address)`.
5. Execution reaches line 366 of `pool.cairo`: `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())` where `reward_address = 0`.
6. STRK rewards are transferred to address zero and are permanently unrecoverable — unclaimed yield is frozen forever.

### Citations

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

**File:** src/pool/pool.cairo (L339-366)
```text
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/staking/staking.cairo (L288-342)
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
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from staker. Sufficient approvals is a pre-condition.
            let staking_contract = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: staker_address, recipient: staking_contract, amount: amount.into(),
                );

            self
                .initialize_staker_own_balance_trace(
                    :staker_address, own_balance: normalized_amount,
                );

            // Create the record for the staker.
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );

            // Update the operational address mapping, which is a 1 to 1 mapping.
            self.operational_address_to_staker_address.write(operational_address, staker_address);
```

**File:** src/staking/staking.cairo (L411-430)
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
```
