### Title
Unvalidated `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `staking.cairo` accepts a caller-controlled `disable_rewards: bool` parameter with no access control. When set to `true`, the function advances the global `last_reward_block` checkpoint but skips reward distribution entirely. Because `last_reward_block` is a single global slot checked at the top of the function, one attacker call per block permanently consumes that block's reward slot for all stakers.

---

### Finding Description

`update_rewards` is exposed as a public function under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

Inside the function, `last_reward_block` is written to the current block number **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately after that write, distributing nothing: [3](#0-2) 

Because the guard at the top of the function asserts `current_block_number > last_reward_block`, once the slot is consumed by the attacker's call, every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. The rewards for that block are permanently unrecoverable.

The analog to the external report is direct: just as `assignTeam` used the caller-supplied `_team` for accounting without validating it against stored state, `update_rewards` uses the caller-supplied `disable_rewards` to gate accounting without validating that the caller is authorized to suppress rewards. In both cases an unvalidated parameter silently corrupts the accounting outcome.

---

### Impact Explanation

An attacker calling `update_rewards(valid_staker, disable_rewards: true)` in every block prevents all stakers from ever receiving consensus block rewards. Each affected block's rewards are permanently lost — they are never minted or transferred. This constitutes **permanent freezing of unclaimed yield** for the entire staker set.

---

### Likelihood Explanation

- No special role or privilege is required; any non-zero address suffices.
- Valid staker addresses are publicly enumerable from the `stakers` storage vector.
- The call is cheap and can be repeated every block.
- The attacker gains nothing financially, making this a pure griefing vector, but the damage to the protocol is severe and irreversible on a per-block basis.

---

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated sequencer address), or split the function so that only a privileged role can pass `disable_rewards: true`. At minimum, the `disable_rewards` branch should not advance `last_reward_block` when rewards are suppressed, so that a legitimate caller can still distribute rewards in the same block.

---

### Proof of Concept

1. Attacker reads any active staker address from the public `stakers` vector.
2. In block N (after consensus rewards are active), attacker calls:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
3. `last_reward_block` is set to N; no rewards are distributed.
4. The legitimate sequencer/node call to `update_rewards(staker_address, false)` in block N reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 
5. All stakers receive zero block rewards for block N.
6. Attacker repeats every block → all consensus block rewards are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L1447-1452)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
