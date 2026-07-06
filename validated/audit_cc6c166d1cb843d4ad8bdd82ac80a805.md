### Title
Unprivileged caller can permanently freeze all consensus block rewards by calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract carries no access control beyond "contract not paused" and "caller not zero address." Any unprivileged address can call it with `disable_rewards: true` every block, causing `last_reward_block` to be advanced without distributing any rewards. Because `last_reward_block` is a single global variable, one such call per block permanently prevents all stakers from receiving consensus rewards.

---

### Finding Description

`StakingRewardsManagerImpl::update_rewards` is embedded in the public ABI and is callable by any non-zero address:

```cairo
// src/staking/staking.cairo  (lines ~1447-1507)
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();          // only: not-paused + not-zero-caller
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        // ← last_reward_block is written BEFORE the disable_rewards branch
        self.last_reward_block.write(current_block_number);

        if disable_rewards || self.is_pre_consensus() {
            return;                            // ← exits without distributing rewards
        }
        ...
    }
}
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [2](#0-1) 

`last_reward_block` is a single global storage slot, not per-staker:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The execution path is:

1. Attacker calls `update_rewards(any_active_staker, disable_rewards: true)`.
2. `last_reward_block` is set to the current block number.
3. The function returns early — no rewards are distributed to any staker.
4. Any legitimate call to `update_rewards` for the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block permanently suppresses all consensus reward distribution.

The only precondition the attacker must satisfy is supplying a valid, active staker address with non-zero STRK balance — trivially satisfied by reading any existing staker from on-chain state.

---

### Impact Explanation

`last_reward_block` is global. A single griefing call per block prevents **all** stakers and their delegators from accruing consensus rewards. Sustained over time this constitutes **permanent freezing of unclaimed yield** for every participant in the protocol, matching the allowed impact: *"High: Permanent freezing of unclaimed yield or unclaimed royalties."*

---

### Likelihood Explanation

**High.** The attacker requires:
- No stake, no special role, no prior inclusion in any process.
- Only a valid staker address (publicly readable) and enough gas to call the function once per block.

On Starknet, per-block gas costs are low, making sustained griefing economically feasible.

---

### Recommendation

Restrict `update_rewards` to an authorized caller — for example, a dedicated consensus-rewards role or the attestation contract — using the existing `RolesComponent`. The `disable_rewards` flag should only be settable by a trusted system actor, not by arbitrary external callers.

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_rewards_distributor(); // add a dedicated role
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the external interface entirely and derive it internally from on-chain attestation state.

---

### Proof of Concept

```
// Attacker script (pseudo-code, executed once per block)
loop {
    staking.update_rewards(
        staker_address = <any_active_staker>,
        disable_rewards = true
    );
    // last_reward_block = current_block; no rewards distributed
    // All legitimate update_rewards calls for this block now revert
    wait_for_next_block();
}
```

After this loop runs continuously, `last_reward_block` always equals the latest block, `_update_rewards` is never reached, and no staker or delegator accumulates any consensus-era yield.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
