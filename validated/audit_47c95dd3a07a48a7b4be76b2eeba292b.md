### Title
Staker Can Atomically Inflate Commission and Trigger Reward Distribution to Steal Delegator Yield - (File: src/staking/staking.cairo)

### Summary
A staker with an active commission commitment can atomically increase their commission to `max_commission`, call the publicly accessible `update_rewards` to distribute rewards at the inflated rate, then decrease commission back — all within a single transaction. Delegators never observe the elevated commission, yet their yield is silently redirected to the staker as commission.

### Finding Description

**Root cause — commission is snapshotted at call time with no delay guard:**

`update_rewards` reads the current commission from storage at the moment it executes: [1](#0-0) 

`set_commission` writes the new commission to storage immediately with no time-lock: [2](#0-1) 

`update_rewards` has no access control — any caller can invoke it once per block: [3](#0-2) 

**Commission commitment enables upward commission changes:**

Without an active commitment, commission can only decrease: [4](#0-3) 

With an active commitment, commission may be set to any value up to `max_commission` (including higher than the current value): [5](#0-4) 

The commitment constraint when it is set only requires `max_commission >= current_commission`: [6](#0-5) 

**Attack sequence (single multicall / proxy transaction):**

1. Staker has commission = 5 % and holds an active commitment with `max_commission = 10000` (100 %).
2. In one atomic transaction the staker's proxy contract calls:
   - `set_commission(10000)` → commission written to storage as 100 %
   - `update_rewards(staker_address, false)` → `calculate_staker_pools_rewards` reads commission = 100 %, all pool rewards flow to the staker as commission, zero reaches the pool
   - `set_commission(500)` → commission restored to 5 %
3. On-chain state before and after shows commission = 5 %; delegators observe nothing unusual.

The reward split happens inside `_update_rewards` → `calculate_staker_pools_rewards`: [7](#0-6) 

Pool rewards are transferred to the pool contract immediately: [8](#0-7) 

Because commission was 100 % at that instant, `pool_rewards = 0` and `commission_rewards = all`, so the pool receives nothing and delegators' yield is permanently lost for that block.

### Impact Explanation
Direct theft of unclaimed yield from delegators. For every block in which the attack is executed, delegators receive zero pool rewards while the staker captures the full pool allocation as commission. The loss is permanent — there is no mechanism to reclaim rewards once distributed.

### Likelihood Explanation
The staker must have previously called `set_commission_commitment` with a `max_commission` above the current commission. This is a deliberate, on-chain, observable setup step. However, the commitment window can span up to one year: [9](#0-8) 

During that entire window the staker can execute the attack on any block where they are first to call `update_rewards`. Because `update_rewards` is permissionless and the staker controls the timing, the attack is repeatable at will throughout the commitment period.

### Recommendation
Record the block number (or epoch) of the last commission change and require that at least one block (or one epoch) has elapsed before the new commission is used in `update_rewards`. Concretely, store a `commission_last_changed_block` alongside the commission value and add a guard in `update_rewards` / `calculate_staker_pools_rewards` that falls back to the previous commission if the change occurred in the current block.

### Proof of Concept

```
// Proxy contract (Cairo pseudocode)
fn exploit(staking: IStakingDispatcher, staker: ContractAddress) {
    // Step 1 – inflate commission to max within active commitment
    staking.set_commission(10000);          // 100%

    // Step 2 – distribute rewards; commission snapshot = 100%
    staking.update_rewards(staker, false);  // all pool rewards → staker as commission

    // Step 3 – restore commission; on-chain view unchanged
    staking.set_commission(500);            // 5%
}
```

Delegators querying `pool_member_info_v1` before and after see `unclaimed_rewards` unchanged (zero new rewards), while the staker's `unclaimed_rewards_own` increases by the full pool allocation for that block.

### Citations

**File:** src/staking/staking.cairo (L772-776)
```text
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
```

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1583-1589)
```text
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
```

**File:** src/staking/staking.cairo (L1595-1596)
```text
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
```

**File:** src/staking/staking.cairo (L1599-1600)
```text
            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/staking.cairo (L1769-1770)
```text
        }

```

**File:** src/staking/staking.cairo (L1964-1964)
```text
            let commission = staker_pool_info.commission();
```

**File:** src/staking/staking.cairo (L1989-1993)
```text
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
```

**File:** src/staking/staking.cairo (L2355-2365)
```text
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```
