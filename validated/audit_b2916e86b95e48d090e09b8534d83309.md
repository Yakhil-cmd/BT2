### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Freeze All Staker Consensus Yield - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function is publicly callable by any non-zero address. It unconditionally writes the current block number to the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. An attacker can call `update_rewards(valid_staker, disable_rewards: true)` once per block, consuming the per-block reward slot without distributing any rewards, permanently preventing all stakers from receiving consensus-phase yield.

---

### Finding Description

`update_rewards` is exposed via the `IStakingRewardsManager` public interface with no role-based access control — `general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function enforces a global per-block gate using `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

This means a call with `disable_rewards: true` silently consumes the reward slot for the current block — `last_reward_block` is advanced, no rewards are minted, and the assertion `current_block_number > last_reward_block` will now fail for every subsequent caller in the same block, including the legitimate consensus mechanism.

The `disable_rewards` parameter is documented as a way to skip reward distribution, but because the global gate is updated unconditionally, any caller can weaponize it: [4](#0-3) 

---

### Impact Explanation

An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` in every block permanently prevents every staker from accumulating consensus rewards. The `last_reward_block` variable is global — not per-staker — so a single poisoned call per block locks out the entire reward pipeline for all participants. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators in the protocol.

---

### Likelihood Explanation

- **Caller requirement:** Any non-zero address; no role, no stake, no special permission needed.
- **Input requirement:** One valid, active, V3-migrated staker address — trivially obtained from on-chain events (`NewStaker`, `stakers` vector).
- **Cost:** One transaction per block on Starknet (low gas cost).
- **Detectability:** The attack is silent; no error is emitted, and `last_reward_block` advancing looks identical to a legitimate reward update.

Likelihood is **high**.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that a no-op call does not consume the block's reward slot:

```cairo
// Update last block rewards ONLY when rewards are actually distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... reward calculation follows
```

Alternatively, restrict `update_rewards` to an authorized caller (e.g., the consensus contract address) so that the `disable_rewards` flag cannot be abused by arbitrary actors.

---

### Proof of Concept

1. Attacker observes any valid, active, V3-migrated staker address `S` from on-chain events.
2. At the start of every new block, attacker submits: `staking.update_rewards(S, disable_rewards: true)`.
3. Inside `update_rewards`:
   - `general_prerequisites()` passes (contract not paused, caller non-zero). [5](#0-4) 
   - `current_block_number > last_reward_block` passes (new block). [2](#0-1) 
   - Staker validity checks pass. [6](#0-5) 
   - `last_reward_block` is written to `current_block_number`. [7](#0-6) 
   - Function returns early — zero rewards distributed. [8](#0-7) 
4. Any subsequent call to `update_rewards` in the same block (including by the legitimate consensus mechanism) hits `REWARDS_ALREADY_UPDATED` and reverts.
5. Repeated every block → all stakers permanently receive zero consensus rewards; `unclaimed_rewards_own` never increases.

### Citations

**File:** src/staking/staking.cairo (L1448-1458)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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

**File:** src/staking/staking.cairo (L1466-1482)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
