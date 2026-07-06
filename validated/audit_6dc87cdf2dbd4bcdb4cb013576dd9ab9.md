### Title
Unrestricted `disable_rewards` Flag Allows Any Caller to Permanently Freeze All Staker Consensus Yield — (`File: src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no access control. When `true`, the function advances the global `last_reward_block` checkpoint (consuming the block's one-time reward slot) but skips actual reward distribution. Because the contract enforces a strict one-call-per-block invariant via `last_reward_block`, any unprivileged attacker can call `update_rewards(valid_staker, true)` once per block to permanently prevent every staker from receiving consensus rewards.

---

### Finding Description

`update_rewards` is the consensus-era (V3) reward distribution entry point. Its logic is:

1. Assert `current_block_number > last_reward_block` — only one successful call per block.
2. Validate the supplied `staker_address` is active and has non-zero balance.
3. **Write `last_reward_block = current_block_number`** — consuming the block slot.
4. If `disable_rewards || is_pre_consensus()` → **return early, distributing nothing**.
5. Otherwise, calculate and distribute block rewards to the staker and its pools. [1](#0-0) 

The global `last_reward_block` is a single contract-wide value, not per-staker: [2](#0-1) 

The only access guard is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [3](#0-2) 

There is no check that the caller is the staker, the staker's operational address, the attestation contract, or any other authorized party. The `disable_rewards` flag is fully attacker-controlled.

**Inconsistency (BSB22 analog):** The function is designed to atomically perform two operations — (1) advance `last_reward_block` and (2) distribute rewards. In the normal path both happen. When `disable_rewards=true` is injected by an attacker, only operation (1) occurs. The block slot is permanently consumed with no rewards issued, mirroring the BSB22 pattern where a property meant to be applied in two positions is applied in only one.

---

### Impact Explanation

- `last_reward_block` is global. One attacker call per block with `disable_rewards=true` exhausts the entire block's reward opportunity for **all** stakers.
- An attacker repeating this every block causes **permanent, continuous freezing of all consensus-era unclaimed yield** across the entire protocol.
- Stakers and delegators accumulate zero rewards indefinitely while their funds remain locked.
- This maps directly to the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is `#[abi(embed_v0)]` — publicly callable by any non-zero address.
- The attacker needs only a valid active staker address (publicly readable from `stakers` vec) and enough gas to call once per block.
- No capital, no privileged key, no bridge interaction is required.
- On Starknet L2, per-block gas cost is low, making sustained griefing economically viable.
- Likelihood: **High**.

---

### Recommendation

Restrict who may supply `disable_rewards=true`. Options:

1. **Remove the parameter entirely** from the public ABI and derive the flag internally (e.g., from whether the staker attested in the current epoch).
2. **Add an access check** so only the staker's own address, operational address, or an authorized contract (e.g., the attestation contract) may call `update_rewards` with `disable_rewards=true`.
3. **Separate the two operations**: advance `last_reward_block` only when rewards are actually distributed, or use a per-staker reward-block tracker instead of a global one.

---

### Proof of Concept

```
// Attacker script (runs once per block):
// 1. Read any valid active staker address from staking.stakers[0]
let victim = staking.stakers.at(0);

// 2. Call update_rewards with disable_rewards=true
// No special permissions needed — general_prerequisites() only checks caller != 0
staking.update_rewards(staker_address: victim, disable_rewards: true);

// Result:
// - last_reward_block is now set to current_block_number
// - No rewards distributed to victim or any pool
// - Any subsequent update_rewards call in this block reverts with REWARDS_ALREADY_UPDATED
// - Repeat every block → all stakers earn zero consensus rewards indefinitely
``` [4](#0-3) [5](#0-4)

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
