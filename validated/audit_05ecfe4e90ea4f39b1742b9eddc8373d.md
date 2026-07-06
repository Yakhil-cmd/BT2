### Title
Caller-Controlled `disable_rewards` Flag Allows Any Address to Consume the Per-Block Reward Slot Without Distributing Rewards - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is publicly callable with no access control beyond a pause/non-zero-caller check. It accepts a caller-controlled `disable_rewards` boolean. When `true`, the function advances the global `last_reward_block` to the current block **before** checking the flag, then returns early without distributing any rewards. Because `last_reward_block` is a single global slot shared across all stakers, one attacker call per block permanently consumes that block's reward opportunity for every staker in the protocol.

### Finding Description
The function signature and guard logic are:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // ← written BEFORE disable check

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← early exit, no rewards sent
    }
    // reward distribution happens here
}
``` [1](#0-0) 

`general_prerequisites()` only enforces pause state and a non-zero caller: [2](#0-1) 

The global `last_reward_block` is declared as a single storage slot: [3](#0-2) 

**Attack path:**
1. At the first transaction of block N, attacker calls `update_rewards(any_active_staker, disable_rewards=true)`.
2. `last_reward_block` is written to N.
3. Every subsequent call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number > last_reward_block` is now false.
4. No staker in the protocol receives consensus block rewards for block N.
5. Attacker repeats at block N+1, N+2, … at the cost of one cheap Starknet transaction per block.

The analog to the external report's vulnerability class is direct: in the external case, the caller supplies both the proof and the root, making the validation trivially satisfiable and bypassing state checks. Here, the caller supplies `disable_rewards=true`, which trivially bypasses the reward-distribution step while still consuming the one-per-block guard slot — the "anchor" (`last_reward_block`) is updated by the attacker's own call, just as the external vulnerability's root was set by the attacker's own call.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.** If sustained (one cheap transaction per block), no staker or delegator ever accumulates consensus rewards. All `unclaimed_rewards_own` and pool `cumulative_rewards_trace` entries remain frozen at their current values indefinitely. Stakers and delegators cannot earn yield they are entitled to.

### Likelihood Explanation
**High.** The function is permissionlessly callable. There is no economic barrier: the attacker needs only one low-cost Starknet transaction per block. No privileged key, bridge access, or external dependency is required. Any address (including a freshly deployed contract) can execute this.

### Recommendation
Restrict who may call `update_rewards` with `disable_rewards=true`, or decouple the `last_reward_block` write from the early-return path so that a `disable_rewards=true` call does not consume the per-block slot:

```cairo
// Option A: only update last_reward_block when rewards are actually distributed
if !disable_rewards && !self.is_pre_consensus() {
    self.last_reward_block.write(current_block_number);
    // ... distribute rewards
}

// Option B: add access control
assert!(
    get_caller_address() == self.attestation_contract.read() || ...,
    "{}",
    Error::UNAUTHORIZED,
);
```

### Proof of Concept
1. Deploy or use any EOA on Starknet.
2. Identify any currently active staker address `S` (readable from `stakers` vec or events).
3. At the start of each block, call `staking_contract.update_rewards(S, disable_rewards=true)`.
4. Observe that `last_reward_block` advances to the current block.
5. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeat every block — all stakers accumulate zero consensus rewards indefinitely.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1508)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
    }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
