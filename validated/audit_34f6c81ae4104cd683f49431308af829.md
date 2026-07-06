### Title
Missing Zero-Address Validation for `reward_address` in `change_reward_address` Enables Permanent Freezing of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
The `change_reward_address` function in both the staking contract and the pool contract does not validate that the supplied `reward_address` is non-zero. A staker or pool member can set their reward address to the zero address, causing all subsequent reward transfers to revert (since the STRK ERC20 rejects transfers to address zero), permanently freezing their unclaimed yield and blocking `unstake_action`.

### Finding Description
In `src/staking/staking.cairo`, `change_reward_address` only checks that the new address is not a token contract address, but performs no zero-address check: [1](#0-0) 

The only guard present is: [2](#0-1) 

After this, `reward_address` is written directly to storage with no further validation. The same pattern exists in the pool contract: [3](#0-2) 

When rewards are later disbursed, `send_rewards_to_staker` calls `checked_transfer` directly to the stored `reward_address` with no zero guard: [4](#0-3) 

`unstake_action` calls `send_rewards_to_staker` as a mandatory step before removing the staker record: [5](#0-4) 

If `reward_address` is zero and the STRK ERC20 reverts on zero-address transfers (standard OpenZeppelin behavior), `unstake_action` will always revert, blocking the staker from recovering their principal. The same issue applies to the pool's `claim_rewards`: [6](#0-5) 

Additionally, the initial `stake` function also lacks a zero-address check for `reward_address`: [7](#0-6) 

### Impact Explanation
A staker who sets (or initially stakes with) `reward_address = 0` will find that:
1. `claim_rewards` reverts — unclaimed yield is permanently frozen.
2. `unstake_action` reverts — the staker cannot exit and recover their principal, constituting a temporary (and practically permanent if unnoticed) freeze of staked funds.

This matches **High: Permanent freezing of unclaimed yield** and **High: Temporary freezing of funds** from the allowed impact scope. While the staker can call `change_reward_address` again to recover (since no `unstake_time` guard exists on that function), a staker who has already called `unstake_intent` and is waiting in the exit window may not realize the cause of the revert, leading to effective permanent loss of yield.

### Likelihood Explanation
Any staker or pool member — an unprivileged actor — can trigger this by calling `change_reward_address(0)` or by supplying zero as `reward_address` at initial `stake`/`enter_delegation_pool` time. No privileged access is required. The likelihood is **Low-Medium**: accidental zero-address input is a realistic user error (e.g., passing an uninitialized variable), and the protocol provides no guard to prevent it.

### Recommendation
Add a non-zero assertion in `change_reward_address` in both contracts, and in the `stake` / `enter_delegation_pool` entry points:

```cairo
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

This mirrors the pattern already used elsewhere in the codebase, e.g.: [8](#0-7) 

### Proof of Concept

**Staking contract path:**
1. Staker calls `stake(reward_address: 0, ...)` — no zero check, succeeds.
   OR staker calls `change_reward_address(reward_address: 0)` — no zero check, succeeds.
2. Rewards accumulate in `unclaimed_rewards_own`.
3. Staker calls `unstake_intent()` — succeeds, sets `unstake_time`.
4. After the exit window, anyone calls `unstake_action(staker_address)`.
5. Inside `unstake_action`, `send_rewards_to_staker` calls `checked_transfer(recipient: 0, amount: rewards)`.
6. STRK ERC20 reverts on zero-address recipient — `unstake_action` reverts.
7. The staker's principal and all unclaimed yield are frozen. The staker must discover the cause and call `change_reward_address` with a valid address before `unstake_action` can succeed.

**Pool contract path:**
1. Pool member calls `change_reward_address(0)` — no zero check, succeeds.
2. Pool member calls `exit_delegation_pool_intent()`.
3. Pool member calls `exit_delegation_pool_action()` — internally calls `claim_rewards` which calls `checked_transfer(recipient: 0, ...)` — reverts.
4. Pool member's unclaimed yield is permanently frozen until they call `change_reward_address` with a valid address. [9](#0-8) [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L493-498)
```text
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/staking/staking.cairo (L517-540)
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

            // Emit event.
            self
                .emit(
                    Events::StakerRewardAddressChanged {
                        staker_address, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1621-1626)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/staking/staking.cairo (L2184-2191)
```text
        fn get_staker_address_by_operational(
            self: @ContractState, operational_address: ContractAddress,
        ) -> ContractAddress {
            let staker_address = self
                .operational_address_to_staker_address
                .read(operational_address);
            assert!(staker_address.is_non_zero(), "{}", Error::STAKER_NOT_EXISTS);
            staker_address
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L505-526)
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

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardAddressChanged {
                        pool_member, new_address: reward_address, old_address,
                    },
                );
        }
```
