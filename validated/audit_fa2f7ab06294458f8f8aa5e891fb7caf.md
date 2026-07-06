### Title
Pool Contract `claim_rewards` Bypasses Staking Contract Pause — (`File: src/pool/pool.cairo`)

### Summary
The `Pool` contract contains no pause checks whatsoever. While most pool write functions that call into the staking contract will revert indirectly (because the staking contract checks `is_paused`), the pool's `claim_rewards` function does **not** call any staking-contract function that enforces the pause guard. It reads entirely from pool-local storage and transfers STRK directly, so it executes successfully even when the staking contract is paused.

### Finding Description
The staking contract exposes a `pause` / `unpause` mechanism controlled by the security agent and security admin. Every state-changing function in the staking contract asserts `!is_paused()` before proceeding. The spec explicitly lists `CONTRACT_IS_PAUSED` as an error condition for pool operations such as `add_to_delegation_pool` and `exit_delegation_pool_intent`.

The `Pool` contract, however, contains **zero** pause checks:

```
grep "is_paused|assert_not_paused|CONTRACT_IS_PAUSED" src/pool/**/*.cairo
→ No matches found.
``` [1](#0-0) 

The `claim_rewards` function in the pool:
1. Reads `pool_member_info` from pool-local storage. [2](#0-1) 
2. Calls `get_current_checkpoint` → `get_current_epoch` on the staking contract — a **view** function that does not check pause. [3](#0-2) 
3. Calculates rewards from the pool's own `cumulative_rewards_trace`. [4](#0-3) 
4. Transfers STRK tokens directly from the pool contract's balance to the reward address. [5](#0-4) 

None of these steps touch a staking-contract function that enforces the pause guard. The STRK tokens are already held by the pool contract (deposited via `update_rewards_from_staking_contract`), so the ERC-20 transfer succeeds unconditionally.

By contrast, the staking contract's own `claim_rewards` is guarded by the pause check, as confirmed by the pause test suite: [6](#0-5) 

The spec requires `CONTRACT_IS_PAUSED` to be an error for pool operations (e.g., `add_to_delegation_pool` precondition "Staking contract is unpaused"): [7](#0-6) 

### Impact Explanation
When the security agent pauses the staking contract — typically in response to a discovered bug such as a reward over-calculation — pool members can still call `Pool::claim_rewards` and drain the STRK tokens already sitting in the pool contract. This directly undermines the emergency pause mechanism and can result in pool members extracting inflated or otherwise incorrect rewards that the pause was intended to freeze. This maps to **High: Theft of unclaimed yield** — the pause is the protocol's last line of defense against reward drainage, and the pool contract bypasses it entirely for reward claims.

### Likelihood Explanation
**Medium.** The staking contract must first be paused (an emergency action by the security agent). Once paused, any pool member or their reward address can immediately call `Pool::claim_rewards` to extract rewards. No special privilege or front-running is required — the entry path is a standard public function callable by any delegator.

### Recommendation
Add a pause propagation check inside `Pool::claim_rewards` (and, for completeness, `enter_delegation_pool`, `add_to_delegation_pool`, and `exit_delegation_pool_intent`) that queries `IStakingDispatcher::is_paused()` and reverts with `CONTRACT_IS_PAUSED` if the staking contract is paused. This mirrors the pattern already enforced on the staking side and aligns the pool contract with the spec's stated preconditions.

### Proof of Concept
1. Deploy the system normally and stake/delegate so that rewards accumulate in the pool contract.
2. Security agent calls `staking.pause()` — e.g., in response to a discovered reward calculation bug.
3. Verify `staking.is_paused()` returns `true`.
4. As a pool member (or their reward address), call `pool.claim_rewards(pool_member)`.
5. Observe that the call **succeeds** and STRK tokens are transferred to the reward address, despite the staking contract being paused.
6. Confirm that calling `staking.claim_rewards(staker_address)` directly reverts with `"Contract is paused"` — demonstrating the asymmetry.

The pool's `claim_rewards` reads only pool-local storage and calls only the view function `get_current_epoch`, neither of which enforces the pause guard, so step 4 completes successfully regardless of the staking contract's paused state. [1](#0-0)

### Citations

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

**File:** docs/spec.md (L1935-1940)
```markdown
6. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
#### pre-condition <!-- omit from toc -->
1. Staker is active and not in an exit window.
2. `pool_member` listed in the contract.
3. `pool_member` has enough funds.
4. Staking contract is unpaused.
```
