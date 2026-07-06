### Title
Single-Step Reward Address Change Allows Permanent Loss of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
Both `change_reward_address` functions in `staking.cairo` and `pool.cairo` implement a single-step address change with no confirmation from the new address. If a staker or pool member accidentally passes a wrong address, all future rewards (and any rewards triggered by `unstake_action` / `exit_delegation_pool_action`) will be irrecoverably sent to that wrong address. The protocol already demonstrates awareness of this risk class by implementing a two-step pattern for `change_operational_address` (`declare_operational_address` + `change_operational_address`), but applies no equivalent safeguard to reward address changes.

### Finding Description
`change_reward_address` in `staking.cairo` (lines 517–540) and `pool.cairo` (lines 505–526) each perform a single-step, immediately-effective address replacement. The only validation performed is that the new address is not a registered token address (`REWARD_ADDRESS_IS_TOKEN`). There is no:
- Zero-address check
- Confirmation step requiring the new address to accept
- Pending/two-step pattern

In contrast, `change_operational_address` (staking.cairo lines 665–703) requires the new operational address to first call `declare_operational_address` (lines 705–723), proving it controls the address before the staker can commit the change. No such safeguard exists for reward addresses.

The reward address is the sole destination for all reward token transfers:
- `send_rewards_to_staker` (staking.cairo line 1625) transfers directly to `staker_info.reward_address`
- `claim_rewards` in pool.cairo (line 366) transfers directly to `pool_member_info.reward_address`
- `unstake_action` (staking.cairo line 495) calls `send_rewards_to_staker` automatically, with no opportunity to correct a wrong address before the transfer executes

### Impact Explanation
If a staker or pool member calls `change_reward_address` with a wrong address (typo, dead address, or address(0)):

1. Any subsequent `claim_rewards` call sends accumulated unclaimed yield to the wrong address — permanently lost.
2. `unstake_action` and `exit_delegation_pool_action` automatically trigger reward transfers to the wrong address as part of the exit flow, with no intermediate step to catch the error.

While the staker can call `change_reward_address` again to correct the stored address, any rewards already transferred to the wrong address are irrecoverable. This constitutes **permanent theft/freezing of unclaimed yield**, matching the allowed High impact scope.

### Likelihood Explanation
Low — identical to M-04. Requires an error on the staker's or pool member's side (e.g., a typo, clipboard error, or wrong address passed programmatically). The risk is elevated by the absence of any confirmation mechanism, which is the exact pattern the protocol already uses for operational address changes.

### Recommendation
Apply the same two-step pattern already used for `change_operational_address`:

1. Add a `declare_reward_address(staker_address)` function that the new reward address must call first, recording it as "pending."
2. Modify `change_reward_address` to only accept an address that has been declared as pending for the calling staker/pool member.

Alternatively, at minimum, add a zero-address guard and emit a time-locked event that allows off-chain monitoring to catch mistakes before rewards are claimed.

### Proof of Concept

**Staker scenario (staking.cairo):**

```
1. Staker stakes via stake(), accumulates rewards over epochs.
2. Staker calls change_reward_address(0xDEAD_ADDRESS) — a typo.
   → staker_info.reward_address = 0xDEAD_ADDRESS (immediate, no confirmation)
3. Staker calls unstake_intent(), waits exit_wait_window.
4. Anyone calls unstake_action(staker_address).
   → send_rewards_to_staker() fires automatically:
      token.transfer(recipient: 0xDEAD_ADDRESS, amount: unclaimed_rewards_own)
   → All accumulated rewards are permanently lost.
```

**Pool member scenario (pool.cairo):**

```
1. Pool member delegates, accumulates rewards.
2. Pool member calls change_reward_address(0xDEAD_ADDRESS).
   → pool_member_info.reward_address = 0xDEAD_ADDRESS (immediate)
3. Pool member calls claim_rewards(pool_member).
   → reward_token.checked_transfer(recipient: 0xDEAD_ADDRESS, amount: rewards)
   → All accumulated pool rewards are permanently lost.
```

**Root cause references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Contrast with the two-step operational address pattern already in place:** [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/staking/staking.cairo (L665-703)
```text
        fn change_operational_address(
            ref self: ContractState, operational_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(
                self.eligible_operational_addresses.read(operational_address) == staker_address,
                "{}",
                Error::OPERATIONAL_NOT_ELIGIBLE,
            );

            // Set operational address and write to storage.
            let old_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(old_address, Zero::zero());
            staker_info.operational_address = operational_address;
            self.write_staker_info(:staker_address, :staker_info);
            self.operational_address_to_staker_address.write(operational_address, staker_address);

            // Emit event.
            self
                .emit(
                    Events::OperationalAddressChanged {
                        staker_address, new_address: operational_address, old_address,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L705-722)
```text
        fn declare_operational_address(ref self: ContractState, staker_address: ContractAddress) {
            self.general_prerequisites();
            let operational_address = get_caller_address();
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_IN_USE,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            if self.eligible_operational_addresses.read(operational_address) == staker_address {
                return;
            }
            self.eligible_operational_addresses.write(operational_address, staker_address);
            self.emit(Events::OperationalAddressDeclared { operational_address, staker_address });
```

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
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
