### Title
Staking Contract Pause Not Enforced in DelegationPool `claim_rewards` — Bypass Allows Reward Extraction During Emergency Freeze - (File: `src/pool/pool.cairo`)

---

### Summary

The Staking contract implements a pause mechanism (`is_paused` flag, `assert_is_unpaused()`). Every state-changing function in the Staking contract checks this flag. However, the DelegationPool contract's `claim_rewards()` function neither checks the staking contract's pause status nor calls any staking contract function that would enforce it. A pool member can call `claim_rewards()` directly on the pool contract and extract accumulated STRK rewards even while the staking contract is paused.

---

### Finding Description

The Staking contract enforces a pause guard on all its state-changing functions via `assert_is_unpaused()`: [1](#0-0) 

Every staking function — `stake`, `increase_stake`, `claim_rewards`, `unstake_intent`, `unstake_action`, `add_stake_from_pool`, `remove_from_delegation_pool_intent`, `remove_from_delegation_pool_action`, `switch_staking_delegation_pool`, etc. — calls `assert_is_unpaused()` at entry. This is confirmed by the pause test suite: [2](#0-1) 

Other pool functions that call staking contract state-changing methods inherit the pause check indirectly. For example, `exit_delegation_pool_action` calls `remove_from_delegation_pool_action` on the staking contract, which checks pause: [3](#0-2) 

However, `claim_rewards` in the pool contract does **not** call any staking contract state-changing function. It only reads pool-local state, calculates rewards from the pool's own `cumulative_rewards_trace`, and directly transfers STRK tokens to the reward address: [4](#0-3) 

The only staking contract interaction inside `claim_rewards` is `get_current_epoch()` (called indirectly via `get_current_checkpoint`), which is a pure view function that does not check pause: [5](#0-4) 

The token transfer at the end of `claim_rewards` moves STRK from the pool contract balance to the reward address with no pause gate: [6](#0-5) 

The pool contract has no `is_paused` storage field and no mechanism to query or respect the staking contract's pause state. [7](#0-6) 

---

### Impact Explanation

The pause is a security control intended to freeze all fund movements during an emergency (e.g., a reward calculation exploit, an accounting bug, or a critical vulnerability being patched). When the security agent pauses the staking contract, the intended invariant is that no funds move anywhere in the protocol.

Because `claim_rewards` on the pool contract bypasses this freeze, pool members can drain all accumulated STRK rewards sitting in the pool contract during the pause window. If the pause was triggered precisely because rewards were incorrectly inflated (e.g., due to an accounting bug in `update_rewards_from_staking_contract` or `cumulative_rewards_trace`), pool members can extract those incorrectly minted rewards before the security team can remediate.

**Impact: High — Theft of unclaimed yield.** Pool members extract rewards that should be frozen pending investigation.

---

### Likelihood Explanation

- No special role or privilege is required. Any pool member (or their reward address) can call `claim_rewards(pool_member)` directly on the pool contract.
- The pool contract address is public and callable by anyone.
- The attacker only needs to know the pool contract address and their own pool member address.
- The window of opportunity is the entire duration of the pause.

**Likelihood: High.**

---

### Recommendation

Add a pause check inside the pool's `claim_rewards` function by querying the staking contract's `is_paused()` view before proceeding:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    // Add pause guard:
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
    // ... rest of function
}
```

Alternatively, apply the same guard to `change_reward_address`, which also has no pause check and no staking contract call. [8](#0-7) 

---

### Proof of Concept

1. Security agent calls `staking.pause()` — staking contract is now paused.
2. Attacker (pool member) calls `pool.claim_rewards(attacker_address)` directly on the pool contract.
3. The pool contract executes without any pause check:
   - Reads `pool_member_info` from pool-local storage.
   - Computes rewards from `cumulative_rewards_trace` (pool-local).
   - Calls `STRK_TOKEN.transfer(reward_address, rewards)` — succeeds.
4. STRK rewards are transferred to the attacker's reward address despite the staking contract being paused.
5. Calling `staking.claim_rewards(staker_address)` in the same state would revert with `"Contract is paused"`, confirming the asymmetry. [4](#0-3) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** src/staking/tests/pause_test.cairo (L147-181)
```text
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_claim_rewards_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_dispatcher = IStakingDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_dispatcher.claim_rewards(staker_address: DUMMY_ADDRESS);
}

#[test]
#[should_panic(expected: "Contract is paused")]
fn test_unstake_intent_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_dispatcher = IStakingDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_dispatcher.unstake_intent();
}

#[test]
#[should_panic(expected: "Contract is paused")]
fn test_unstake_action_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_dispatcher = IStakingDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_dispatcher.unstake_action(staker_address: DUMMY_ADDRESS);
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

**File:** src/pool/pool.cairo (L317-319)
```text
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());
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

**File:** src/pool/pool.cairo (L692-697)
```text
        fn get_current_epoch(self: @ContractState) -> Epoch {
            let staking_dispatcher = IStakingDispatcher {
                contract_address: self.staking_pool_dispatcher.contract_address.read(),
            };
            staking_dispatcher.get_current_epoch()
        }
```
