### Title
Missing Staking-Pause Check in Pool Contract's `claim_rewards` Allows Fund Withdrawal During Emergency - (File: `src/pool/pool.cairo`)

---

### Summary

The staking contract exposes a pause mechanism (`is_paused`) that is meant to freeze all fund movements during a security emergency. The staking contract's own `claim_rewards` correctly enforces this via `general_prerequisites()` → `assert_is_unpaused()`. However, the pool contract (`src/pool/pool.cairo`) has no pause check at all. Its `claim_rewards` function transfers STRK tokens out of the pool contract without ever consulting the staking contract's pause state, allowing pool members to drain accrued rewards even while the system is in an emergency freeze.

---

### Finding Description

The staking contract defines `assert_is_unpaused` at line 1657–1659: [1](#0-0) 

Every state-changing function in the staking contract that moves funds calls `general_prerequisites()`, which internally calls `assert_is_unpaused`. For example, `claim_rewards` in the staking contract: [2](#0-1) 

The pause/unpause logic is controlled by the `SECURITY_AGENT` / `SECURITY_ADMIN` roles: [3](#0-2) 

The pause tests confirm that `claim_rewards` on the staking contract is expected to revert when paused: [4](#0-3) 

By contrast, the pool contract's `claim_rewards` function contains **no pause check whatsoever**. It reads from `cumulative_rewards_trace`, computes rewards, and immediately transfers STRK to the reward address: [5](#0-4) 

The pool contract has no `is_paused` storage field, no `assert_is_unpaused` helper, and no call to the staking contract to query its pause state. The grep for `assert_is_unpaused` and `is_paused` in `pool.cairo` returns zero matches.

Similarly, `change_reward_address` in the pool contract has no pause check: [6](#0-5) 

---

### Impact Explanation

When the security agent pauses the staking contract in response to a security incident (e.g., a reward-calculation bug that caused over-allocation of STRK to pool contracts), the intent is to freeze all fund movements. The staking contract's `claim_rewards` is correctly frozen. However, pool members can immediately call `claim_rewards` on the pool contract to withdraw STRK that is already sitting in the pool contract's balance — funds that may represent incorrectly minted or over-allocated rewards. This directly bypasses the emergency freeze and constitutes **theft of unclaimed yield** (High impact).

The pool contract holds STRK rewards sent to it by the staking contract via `send_rewards_to_delegation_pool`. If those rewards were inflated due to a bug, pausing the staking contract does not prevent pool members from claiming them through the pool contract.

---

### Likelihood Explanation

The staking contract's pause mechanism is explicitly designed for security incidents. The pool contract is a core, permissionlessly-deployed contract that every delegator interacts with. Any pool member (unprivileged user) can call `claim_rewards` on their pool contract at any time. During a pause event, a pool member who is aware of the pause (e.g., by monitoring on-chain events) has a direct incentive to call `claim_rewards` on the pool contract before the issue is resolved. The entry path requires no special privileges.

---

### Recommendation

The pool contract's `claim_rewards` (and `change_reward_address`) should check whether the staking contract is paused before proceeding. Since the pool contract already holds a reference to the staking contract via `staking_pool_dispatcher`, it can query `IStakingDispatcher::is_paused()` and assert it returns `false`:

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

The same guard should be applied to `change_reward_address`.

---

### Proof of Concept

1. Deploy the system normally and stake/delegate so that rewards accumulate in a pool contract.
2. Call `staking_pause_dispatcher.pause()` as the security agent — the staking contract is now paused.
3. Confirm that calling `staking_dispatcher.claim_rewards(staker_address)` reverts with `"Contract is paused"`.
4. Call `pool_dispatcher.claim_rewards(pool_member)` directly on the pool contract — this **succeeds** and transfers STRK to the reward address, bypassing the emergency freeze.

The pool contract's `claim_rewards` at lines 335–377 performs no pause check and calls no staking contract function that would trigger the pause guard, so it executes to completion regardless of the staking contract's pause state. [5](#0-4) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L411-413)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1249-1266)
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

        fn unpause(ref self: ContractState) {
            self.roles.only_security_admin();
            if !self.is_paused() {
                return;
            }
            self.is_paused.write(false);
            self.emit(PauseEvents::Unpaused { account: get_caller_address() });
        }
```

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** src/staking/tests/pause_test.cairo (L147-157)
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
