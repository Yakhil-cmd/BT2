### Title
Unprivileged Caller Can Permanently Grief All Stakers' Block Rewards via `update_rewards` with `disable_rewards: true` - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no access control. Its `disable_rewards` parameter is fully caller-controlled. Because the function unconditionally writes the current block number to the global `last_reward_block` storage slot before checking `disable_rewards`, any unprivileged attacker can call `update_rewards(valid_staker, disable_rewards: true)` once per block to consume the per-block reward slot without distributing any rewards, permanently denying all stakers their consensus block rewards.

---

### Finding Description

`update_rewards` is declared in `IStakingRewardsManager` and has no role guard or caller restriction. Its logic is:

1. Check `current_block_number > last_reward_block` (one call allowed per block, globally).
2. Validate the supplied `staker_address` is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`** (unconditional).
4. If `disable_rewards == true` **or** `is_pre_consensus()`, return early — no rewards distributed. [1](#0-0) 

The critical flaw is that step 3 (the global state write) happens **before** the `disable_rewards` branch. Once `last_reward_block` is updated, the assertion at step 1 will reject any subsequent call in the same block: [2](#0-1) 

Because `last_reward_block` is a single global slot (not per-staker), one attacker call per block poisons the slot for every staker in the protocol. [3](#0-2) 

By contrast, the analogous pre-consensus reward path (`update_rewards_from_attestation_contract`) is correctly gated to only the attestation contract: [4](#0-3) 

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users or protocol.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` on every block causes the entire protocol to distribute zero consensus block rewards indefinitely. All stakers and their delegators lose accrued yield for every griefed block. The attacker gains nothing financially; the sole purpose is damage. This falls squarely within the allowed Medium impact category: *"Griefing with no profit motive but damage to users or protocol."*

---

### Likelihood Explanation

**Medium.** The attacker needs only:
- A valid, active staker address (trivially obtained from on-chain events or `get_stakers()`).
- Gas to submit one transaction per block.

No privileged access, no leaked key, no bridge interaction is required. The attack is permissionless and sustainable as long as the attacker is willing to pay gas costs. A well-funded adversary (e.g., a competing protocol or a staker who wants to suppress competitors' rewards) has clear economic motivation.

---

### Recommendation

Add an access-control check to `update_rewards` so that only an authorized caller (e.g., the attestation contract, a designated keeper role, or the staker/operational address itself) can invoke it. Alternatively, move the `last_reward_block.write(...)` call to **after** the `disable_rewards` branch so that a call with `disable_rewards: true` does not consume the per-block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;  // do NOT write last_reward_block here
}
// Only write after confirming rewards will actually be distributed
self.last_reward_block.write(current_block_number);
// ... distribute rewards ...
```

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes any active staker address `S` from on-chain events.
3. At the start of each new block, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function passes all staker-validity checks, writes `last_reward_block = current_block`, then returns early at line 1487 without distributing rewards.
5. Any legitimate call to `update_rewards` for the same block now reverts with `REWARDS_ALREADY_UPDATED` (line 1457).
6. All stakers receive zero block rewards for that block.
7. Repeating step 3 every block results in permanent, protocol-wide reward denial. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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
