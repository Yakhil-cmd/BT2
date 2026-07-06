### Title
Pool `claim_rewards` Bypasses Staking Contract Pause Mechanism - (File: `src/pool/pool.cairo`)

### Summary
The pool contract's `claim_rewards` function does not check whether the staking contract is paused, allowing delegators to claim rewards even during an active emergency pause. This is the direct analog to M-16: a function that should respect a temporary operational restriction does not account for it.

### Finding Description
The staking contract enforces a pause mechanism via `general_prerequisites()`, which is called at the top of every state-changing function including `claim_rewards`, `unstake_intent`, `unstake_action`, etc. When paused, all of these revert with `CONTRACT_IS_PAUSED`.

The pool contract (`src/pool/pool.cairo`) has **no pause check anywhere** — confirmed by the complete absence of `is_paused`, `general_prerequisites`, or `CONTRACT_IS_PAUSED` in the entire pool source tree.

Specifically, `pool::claim_rewards` (lines 335–377) executes the full reward distribution flow — reading pool member state, computing rewards, zeroing them out, and transferring STRK tokens to the reward address — without ever querying the staking contract's pause state:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    // ... no pause check ...
    let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
    reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
    rewards
}
``` [1](#0-0) 

Compare this to the staking contract's own `claim_rewards`, which calls `general_prerequisites()` as its very first action:

```cairo
fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
    self.general_prerequisites();  // reverts if paused
    ...
}
``` [2](#0-1) 

The staking contract's `is_paused` is a public view function callable by anyone: [3](#0-2) 

Other pool operations that call back into the staking contract (e.g., `exit_delegation_pool_intent` → `remove_from_delegation_pool_intent`, `exit_delegation_pool_action` → `remove_from_delegation_pool_action`) are indirectly protected because those staking-side functions also call `general_prerequisites()`. But `claim_rewards` makes no cross-contract call to the staking contract at all, so it is entirely unprotected. [4](#0-3) 

### Impact Explanation
**High — Theft of unclaimed yield.**

The pause mechanism is the protocol's primary emergency control. It is triggered when a security incident is detected (e.g., a reward calculation bug causing over-minting, or an exploit in progress). The intent is to freeze all reward flows until the issue is resolved.

Because `pool::claim_rewards` bypasses the pause, delegators can drain rewards from the pool contract during the exact window when the security team has halted operations. If the pause was triggered because rewards were incorrectly inflated, delegators can claim those inflated rewards before the issue is corrected, constituting direct theft of unclaimed yield from the protocol.

### Likelihood Explanation
**Medium.** The exploit requires the staking contract to be in a paused state, which is an emergency scenario. However, once paused, any delegator — an entirely unprivileged role — can call `pool::claim_rewards` with no special access. The attacker needs only to monitor for a pause event and act before the issue is resolved. No key compromise, governance access, or third-party dependency is required.

### Recommendation
Add a pause check to `pool::claim_rewards` (and defensively to `add_to_delegation_pool`, `change_reward_address`, and `switch_delegation_pool` as well) by querying the staking contract's `is_paused()` before proceeding:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
    // ... rest of function
}
```

### Proof of Concept
1. Staking contract is paused by the security agent (e.g., due to a reward over-minting bug).
2. Delegator observes the `Paused` event on-chain.
3. Delegator calls `pool.claim_rewards(pool_member)` directly on the pool contract.
4. The pool contract executes fully: computes rewards, zeroes out the stored balance, and transfers STRK to the reward address.
5. No revert occurs. The pause is bypassed. Inflated/incorrect rewards are extracted before the protocol can respond. [1](#0-0) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
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

**File:** docs/spec.md (L1274-1285)
```markdown
### is_paused
```rust
fn is_paused(self: @TContractState) -> bool
```
#### description <!-- omit from toc -->
Return `true` if the staking contract is paused.
#### emits <!-- omit from toc -->
#### errors <!-- omit from toc -->
#### pre-condition <!-- omit from toc -->
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
```
