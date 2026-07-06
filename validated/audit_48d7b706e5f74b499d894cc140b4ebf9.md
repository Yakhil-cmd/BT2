### Title
Unrestricted `update_rewards` with `disable_rewards` flag enables permanent freezing of consensus rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is publicly callable by any address with no access-control check. It accepts a `disable_rewards: bool` parameter that, when `true`, still writes the current block number into the global `last_reward_block` storage slot but distributes zero rewards. Because `last_reward_block` is a single protocol-wide variable, one such call per block permanently blocks every staker from receiving consensus rewards for that block. An attacker can repeat this every block to freeze all consensus reward accrual indefinitely.

---

### Finding Description

`update_rewards` is declared as an `#[abi(embed_v0)]` public entry point with no privileged-role guard:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();          // only checks: not paused, caller != 0
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        self.last_reward_block.write(current_block_number);   // ← always written

        if disable_rewards || self.is_pre_consensus() {
            return;                                           // ← exits before distributing
        }
        ...
    }
}
``` [1](#0-0) 

`general_prerequisites` only enforces the pause flag and a non-zero caller — no role check: [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

The guard at the top of `update_rewards` enforces that only **one** call per block can succeed: [4](#0-3) 

When `disable_rewards: true` is passed, `last_reward_block` is still committed to the current block number, consuming the single allowed slot for that block while distributing nothing: [5](#0-4) 

---

### Impact Explanation

In the consensus-rewards phase (`is_pre_consensus()` returns `false`), `update_rewards` is the sole mechanism by which stakers accumulate block rewards. If an attacker calls `update_rewards(<any_valid_staker>, disable_rewards: true)` in every block:

- `last_reward_block` is set to the current block.
- No rewards are distributed.
- Every subsequent legitimate call to `update_rewards` in that block reverts with `REWARDS_ALREADY_UPDATED`.
- Stakers never accumulate consensus rewards; their `unclaimed_rewards_own` never increases.

This constitutes **permanent freezing of unclaimed yield** for all stakers and pool members — a **High** severity impact per the allowed scope. [6](#0-5) 

---

### Likelihood Explanation

- The call requires no tokens, no stake, and no privileged role — only a non-zero address.
- On Starknet, submitting one transaction per block is trivially cheap.
- The attacker has a clear economic motive: a competing staker can freeze all rivals' rewards while their own rewards (accrued via the attestation path in pre-consensus, or via a separate mechanism) remain unaffected.
- No special timing or mempool visibility is required; the attacker simply front-runs every block.

Likelihood: **Medium** (requires sustained on-chain activity but is economically rational for a competing staker).

---

### Recommendation

Add an access-control guard to `update_rewards` so that only the attestation contract or a designated rewards-distributor role may invoke it. Alternatively, remove the `disable_rewards` parameter from the public interface and expose it only through an internal function callable by privileged contracts. The `last_reward_block` slot should only be advanced when rewards are actually distributed or by a trusted caller.

---

### Proof of Concept

1. Consensus rewards are activated (`consensus_rewards_first_epoch` is set, `is_pre_consensus()` returns `false`).
2. Attacker (any EOA) submits, in every block:
   ```
   staking_contract.update_rewards(
       staker_address = <any active staker>,
       disable_rewards = true
   )
   ```
3. Each call passes `general_prerequisites` (not paused, caller non-zero), passes the `last_reward_block` check (new block), writes `last_reward_block = current_block`, then returns early because `disable_rewards == true`.
4. Any legitimate call to `update_rewards` later in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After N blocks, every staker's `unclaimed_rewards_own` remains at zero; pool `cumulative_rewards_trace` is never updated; no yield is ever claimable. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1507)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
