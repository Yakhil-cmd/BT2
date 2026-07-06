### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, which marks the current block as processed and returns early without distributing rewards. Because `last_reward_block` is updated unconditionally, the legitimate sequencer call for that block is permanently blocked, causing the staker to lose block rewards for that slot forever.

### Finding Description
The spec for `update_rewards` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1488 performs no such check:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);   // written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits before distributing
    }
    ...
``` [1](#0-0) 

`general_prerequisites()` only checks whether the contract is paused; it does not verify the caller identity. [2](#0-1) 

The `last_reward_block` write at line 1485 happens before the `disable_rewards` early-return at line 1487, so the block is permanently consumed regardless of whether rewards were actually distributed. [3](#0-2) 

Compare with other privileged setters in the same contract that correctly enforce role checks, e.g. `set_reward_supplier` calls `self.roles.only_token_admin()` before doing anything: [4](#0-3) 

### Impact Explanation
An attacker who calls `update_rewards(victim_staker, disable_rewards: true)` once per block:

1. Writes `last_reward_block = current_block_number`.
2. Returns immediately without crediting any rewards to the staker.
3. Any subsequent call in the same block (including the legitimate sequencer call) reverts with `REWARDS_ALREADY_UPDATED`.

The staker permanently loses the block rewards for every block the attacker front-runs. Because the consensus reward scheme distributes rewards per-block, each missed block represents an irrecoverable loss of unclaimed yield. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The entry path requires no stake, no delegation, no privileged role, and no special setup. Any EOA on Starknet can call `IStakingRewardsManager::update_rewards` at any time. The attacker only needs to submit a transaction before the sequencer's own call in each block. The cost is a single transaction per block; the attacker has no profit motive but causes direct, irreversible damage to stakers.

### Recommendation
Add a sequencer-only guard at the top of `update_rewards`, analogous to the role checks already used elsewhere in the contract:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer();   // <-- add this
    self.general_prerequisites();
    ...
```

Alternatively, restrict the function to a dedicated `SEQUENCER_ROLE` address stored at deployment time, consistent with the existing `RolesComponent` pattern used throughout the contract. [5](#0-4) 

### Proof of Concept

1. Staker `S` stakes and waits K epochs for their balance to become effective.
2. Consensus rewards are activated (`set_consensus_rewards_first_epoch`).
3. Attacker `A` (any address) monitors the mempool and, at each new block, submits:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(S, disable_rewards=true)
   ```
4. `last_reward_block` is set to the current block; the function returns without distributing rewards.
5. The sequencer's legitimate `update_rewards(S, disable_rewards=false)` call reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker `S` receives zero block rewards for that block. Repeating every block permanently freezes all of `S`'s consensus-phase yield.

The test suite itself demonstrates that `update_rewards` is callable by any address with no role restriction — tests call it directly without any `cheat_caller_address` impersonation of a sequencer role: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1294-1295)
```text
        fn set_reward_supplier(ref self: ContractState, reward_supplier: ContractAddress) {
            self.roles.only_token_admin();
```

**File:** src/staking/staking.cairo (L1447-1489)
```text
    #[abi(embed_v0)]
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
```

**File:** src/staking/tests/test.cairo (L3877-3877)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
```
