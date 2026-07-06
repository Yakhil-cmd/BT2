### Title
Missing Pause Check in Pool Contract Allows Reward Claiming During Emergency Stop - (File: src/pool/pool.cairo)

### Summary

The `Pool` contract implements no pause mechanism of its own, and its `claim_rewards` function does not check whether the `Staking` contract is paused before transferring STRK rewards to pool members. When the `Staking` contract is paused by the security agent in response to an emergency, pool members can still call `Pool::claim_rewards` to drain accumulated rewards, bypassing the intended emergency stop entirely.

### Finding Description

The `Staking` contract implements a full emergency stop pattern via `IStakingPause`. The `assert_is_unpaused` helper is called through `general_prerequisites()` at the top of every state-changing function in `Staking`. [1](#0-0) [2](#0-1) 

Most `Pool` functions that move funds do call back into the `Staking` contract (e.g., `enter_delegation_pool` → `add_stake_from_pool`, `exit_delegation_pool_intent` → `remove_from_delegation_pool_intent`), so those calls hit the pause check indirectly.

However, `Pool::claim_rewards` is entirely self-contained. It reads from the pool's own `cumulative_rewards_trace`, computes rewards, updates `pool_member_info` in pool storage, and transfers STRK directly using a hardcoded `STRK_TOKEN_ADDRESS` dispatcher — **without ever calling the `Staking` contract**: [3](#0-2) 

The reward token transfer at line 365–366 goes directly to the reward address with no pause guard: [4](#0-3) 

Similarly, `Pool::change_reward_address` modifies pool member state without any pause check: [5](#0-4) 

The `Pool` contract storage has no `is_paused` field and no equivalent of `assert_is_unpaused`: [6](#0-5) 

### Impact Explanation

**High — Theft of unclaimed yield.**

The pause is the protocol's primary emergency response. If it is triggered because a reward accounting bug caused inflated `cumulative_rewards_trace` entries (e.g., a miscalculation in `update_rewards_from_staking_contract`), every pool member can immediately call `Pool::claim_rewards` and withdraw the inflated rewards before the issue is corrected. The STRK reward tokens held by the pool contract are drained to pool members' reward addresses, constituting theft of unclaimed yield that the protocol cannot recover.

### Likelihood Explanation

**High.** The entry point (`Pool::claim_rewards`) is callable by any pool member or their reward address — no privileged role is required. The pool contract address is public. The moment a pause is broadcast on-chain, any observer can front-run the pause or call `claim_rewards` in the same block or shortly after, since the pool contract itself is never paused.

### Recommendation

Add a pause check to `Pool::claim_rewards` (and `Pool::change_reward_address`) that queries the `Staking` contract's pause state before proceeding:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    // Add pause check:
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
    // ... rest of function
}
```

Alternatively, introduce a mirrored `is_paused` flag in the `Pool` contract that is set/cleared by the `Staking` contract when it pauses/unpauses, so the pool can enforce the pause locally without an external call.

### Proof of Concept

1. Pool member `Alice` has accumulated rewards in pool `P` (staker `S`).
2. Security agent detects a reward inflation bug and calls `Staking::pause()`.
3. `Staking::is_paused` is now `true`.
4. Alice calls `Pool::claim_rewards(alice_address)` on pool `P`.
5. `Pool::claim_rewards` reads `cumulative_rewards_trace`, computes (inflated) rewards, updates `pool_member_info`, and calls `reward_token.checked_transfer(recipient: alice_reward_address, amount: inflated_rewards)` — **no pause check is performed**.
6. Alice receives inflated STRK rewards. The staking contract's pause had zero effect on the pool's reward distribution. [3](#0-2) [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1249-1257)
```text
    impl StakingPauseImpl of IStakingPause<ContractState> {
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }
```

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** src/staking/interface.cairo (L231-239)
```text
#[starknet::interface]
pub trait IStakingPause<TContractState> {
    /// Pause the staking contract.
    /// Pausing the staking contract prevents any state changes (balance changes, staker settings,
    /// etc.)
    fn pause(ref self: TContractState);
    /// Unpause the staking contract.
    fn unpause(ref self: TContractState);
}
```

**File:** src/pool/pool.cairo (L81-124)
```text
    #[storage]
    struct Storage {
        #[substorage(v0)]
        replaceability: ReplaceabilityComponent::Storage,
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        roles: RolesComponent::Storage,
        // ------ Deprecated fields ------
        // Deprecated field from V0. Stores the final global index of staking contract if the
        // staker was active during the upgrade to V1. If the staker was removed in V0, it retains
        // the final staker index.
        // final_staker_index: Option<Index>,
        // Deprecated commission field, was used in V0.
        // commission: Commission,
        // -------------------------------
        /// Address of the staker that the pool is associated with.
        staker_address: ContractAddress,
        /// Map pool member to their pool member info.
        pool_member_info: Map<ContractAddress, VInternalPoolMemberInfo>,
        /// Dispatcher for the staking contract's pool functions.
        staking_pool_dispatcher: IStakingPoolDispatcher,
        /// Pool's token dispatcher.
        token_dispatcher: IERC20Dispatcher,
        /// Map pool member to their epoch-balance info.
        pool_member_epoch_balance: Map<ContractAddress, PoolMemberBalanceTrace>,
        /// Map version to class hash of the contract.
        prev_class_hash: Map<Version, ClassHash>,
        /// Indicates whether the staker has been removed from the staking contract.
        staker_removed: bool,
        /// Maintains a cumulative sum of pool_rewards/pool_balance per epoch for member rewards
        /// calculation.
        /// Updated whenever rewards are received from the staking contract.
        cumulative_rewards_trace: Trace,
        /// Minimum amount of delegation required for rewards.
        /// Used to avoid overflow in the rewards calculation.
        min_delegation_for_rewards: Amount,
        /// Staking rewards base value.
        /// Used in rewards calculation: $$ rewards = amount * interest / base_value $$,
        /// Where `interest` scales with `base_value`.
        staking_rewards_base_value: Amount,
    }
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
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
