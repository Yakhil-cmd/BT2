### Title
Missing Caller Restriction on `update_rewards` Allows Any User to Suppress Staker Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is specified to be callable only by the Starknet sequencer, but the implementation contains no caller check. Any unprivileged user can call it with `disable_rewards: true`, which writes the current block number to `last_reward_block` and skips reward distribution. Because the contract enforces a one-call-per-block invariant (`REWARDS_ALREADY_UPDATED`), the sequencer's legitimate call for that block is then permanently blocked, and the targeted staker loses all rewards for that block.

### Finding Description

The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, `StakingRewardsManagerImpl::update_rewards` in `src/staking/staking.cairo` performs no such check:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...
    self.last_reward_block.write(current_block_number);   // slot consumed here
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // no rewards distributed
    }
    // ... reward distribution ...
``` [1](#0-0) 

The only gate is `general_prerequisites()`, which only checks the pause flag. [2](#0-1) 

The spec's access-control requirement is documented but never enforced in code. [3](#0-2) 

**Attack path:**

1. Attacker observes the mempool (or simply races at the start of each block) and calls `update_rewards(victim_staker, disable_rewards: true)` before the sequencer does.
2. `last_reward_block` is written to the current block number.
3. No rewards are distributed (`disable_rewards == true` causes an early return).
4. When the sequencer subsequently calls `update_rewards(victim_staker, disable_rewards: false)`, the assertion `current_block_number > self.last_reward_block.read()` fails with `REWARDS_ALREADY_UPDATED`, and the call reverts.
5. The staker's `unclaimed_rewards_own` is never incremented for that block. [4](#0-3) 

### Impact Explanation

Each block where the attacker front-runs the sequencer, the targeted staker permanently loses the block rewards that would have been credited to `unclaimed_rewards_own`. The rewards are never minted/transferred to the staker's reward address. This constitutes **theft of unclaimed yield** (the staker is entitled to those rewards but can never claim them). The attack can be repeated every block, causing continuous, compounding loss of yield for any targeted staker.

**Severity: High** — matches "Theft of unclaimed yield or unclaimed royalties."

### Likelihood Explanation

- No privileged access is required; any externally-owned address can call `update_rewards`.
- Staker addresses are public on-chain.
- The attacker only needs to submit a transaction in the same block as the sequencer's `update_rewards` call, with a higher gas price (front-running), which is straightforward on Starknet.
- The attack is cheap (a single transaction per block) and can be sustained indefinitely.

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract()`:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // <-- add this
    ...
}
```

Store the authorized sequencer address in contract storage (set during initialization or via a governance call) and assert `get_caller_address() == self.sequencer_address.read()`.

### Proof of Concept

1. Deploy the system and advance past the consensus rewards epoch.
2. A staker stakes and waits K epochs for their balance to become effective.
3. Attacker (any address) calls:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: victim, disable_rewards: true);
   ```
4. `last_reward_block` is now set to the current block; no rewards credited.
5. Sequencer calls `update_rewards(victim, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
6. `staker_info.unclaimed_rewards_own` remains unchanged; victim receives zero rewards for that block.
7. Repeat step 3 every block to permanently deny all yield to the victim. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1449-1510)
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

    #[generate_trait]
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
