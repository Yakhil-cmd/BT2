### Title
Missing Caller Authorization on `update_rewards` Allows Any Address to Permanently Deny Staker Yield - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is documented in the protocol spec as callable only by the "starkware sequencer," but the implementation contains **no caller check**. Any unprivileged address can call it with `disable_rewards: true`, which writes the current block number to the global `last_reward_block` storage slot without distributing any rewards. Because the function enforces a per-block uniqueness guard (`current_block_number > last_reward_block`), the sequencer's legitimate call for that same block will revert with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's yield for all stakers.

### Finding Description
`IStakingRewardsManager::update_rewards` is the consensus-era reward distribution entry point. The spec explicitly restricts it:

> **access control**: Only starkware sequencer.
> — `docs/spec.md` line 1645

The implementation, however, performs no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ← NO assert_caller_is_sequencer() or equivalent
    ...
    self.last_reward_block.write(current_block_number);   // written BEFORE disable check
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing
    }
    // reward distribution follows
```

The critical ordering is: `last_reward_block` is committed to storage **before** the `disable_rewards` branch. An attacker who calls `update_rewards(any_staker, disable_rewards: true)` in a given block:

1. Passes the `REWARDS_ALREADY_UPDATED` guard (first call in that block).
2. Writes `last_reward_block = current_block`.
3. Returns immediately — zero rewards distributed.
4. The sequencer's subsequent call for the same block fails: `current_block_number > last_reward_block` is now `false`.

Because `last_reward_block` is a **single global slot** (not per-staker), one attacker transaction per block is sufficient to suppress rewards for every staker in that block.

### Impact Explanation
**High — Permanent freezing / theft of unclaimed yield.**

Each block in the consensus-rewards phase produces STRK (and BTC) block rewards proportional to each staker's staking power. When `update_rewards` is front-run with `disable_rewards: true`, those block rewards are never credited to `unclaimed_rewards_own` and never forwarded to delegation pools. The loss is permanent: there is no catch-up mechanism; `last_reward_block` can never be rewound. A sustained attacker (one tx/block) can zero out all consensus-era yield indefinitely.

### Likelihood Explanation
**High.** The function is public, requires no token balance, no staker registration, and no privileged role. The only cost is gas per block. The attacker does not need to be a staker or pool member. The `staker_address` argument can be any currently-active staker (readable from the public `stakers` vector). The attack is trivially scriptable.

### Recommendation
Add an explicit sequencer-only guard at the top of `update_rewards`, mirroring the pattern already used for `update_rewards_from_attestation_contract` (which checks `assert_caller_is_attestation_contract`). Concretely, store the authorized sequencer address in contract storage during initialization and assert `get_caller_address() == self.sequencer_address.read()` as the first statement in `update_rewards`.

### Proof of Concept

**Attacker script (pseudocode, one call per block):**
```
loop every new block:
    staking_contract.update_rewards(
        staker_address = any_active_staker,   // readable from public stakers vec
        disable_rewards = true
    )
```

**Effect trace:**
1. Block N arrives. Attacker calls `update_rewards(staker_X, disable_rewards=true)`.
2. Guard passes: `N > last_reward_block` (e.g., `N > N-1`). ✓
3. `last_reward_block` written to `N`.
4. `disable_rewards == true` → early return. No rewards distributed.
5. Sequencer calls `update_rewards(staker_X, disable_rewards=false)`.
6. Guard fails: `N > N` is false → reverts `REWARDS_ALREADY_UPDATED`.
7. Staker X (and all pool members) receive zero rewards for block N.
8. Repeat for block N+1, N+2, …

**Root cause lines:** [1](#0-0) 

**Spec access-control requirement (violated):** [2](#0-1) 

**Global `last_reward_block` storage slot (single value, not per-staker):** [3](#0-2) 

**Contrast: `update_rewards_from_attestation_contract` correctly enforces caller identity:** [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1370-1380)
```text
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(!is_active, "{}", Error::TOKEN_ALREADY_ENABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, true));
            self.emit(TokenManagerEvents::TokenEnabled { token_address });
        }

        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
```

**File:** src/staking/staking.cairo (L1448-1489)
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
