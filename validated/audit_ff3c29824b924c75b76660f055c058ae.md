### Title
Unprivileged caller can permanently suppress per-block consensus rewards by calling `update_rewards` with `disable_rewards=true` — (File: `src/staking/staking.cairo`)

---

### Summary

`Staking::update_rewards` is a public, permissionless function. It unconditionally writes `last_reward_block = current_block_number` **before** branching on the `disable_rewards` flag. Any unprivileged caller can invoke it with `disable_rewards=true` to consume the block's reward slot without distributing any rewards, permanently destroying that block's yield for every staker.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` follows this sequence:

```cairo
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
    // ... staker validity checks ...

    // ← reward slot consumed HERE, unconditionally
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;   // ← exits with NO rewards distributed
    }

    // reward distribution only reached when disable_rewards == false
    let (strk_block_rewards, btc_block_rewards) = self
        .calculate_block_rewards(...);
    self._update_rewards(...);
}
``` [1](#0-0) 

`last_reward_block` is a **single global** storage slot, not per-staker. The guard at the top of the function (`current_block_number > self.last_reward_block.read()`) enforces exactly one call per block. Once the slot is consumed by a call with `disable_rewards=true`, every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

There is **no access-control check** (`self.roles.only_...()`) anywhere in `update_rewards`. The function is part of the public `IStakingRewardsManager` ABI and accepts an arbitrary `disable_rewards: bool` from the caller. [3](#0-2) 

---

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards=true)` once per block:

1. Marks the block as processed (`last_reward_block = N`).
2. Causes the function to return before `_update_rewards` is reached.
3. Prevents any legitimate call in block N from distributing rewards (all revert with `REWARDS_ALREADY_UPDATED`).
4. The block's yield is **permanently lost** — it is never added to `unclaimed_rewards_own` for any staker or pool.

Sustained over many blocks, this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators. The attacker pays only gas; stakers lose all consensus-era block rewards.

This maps to the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

---

### Likelihood Explanation

- The entry point is fully public; no role, no signature, no stake required.
- The only prerequisite is supplying a valid (active, non-zero-balance) staker address, which is trivially discoverable from on-chain events (`NewStaker`).
- The cost to the attacker is one Starknet transaction per block (~seconds). The cost to victims is the entire consensus reward stream.
- The attack is silent: no anomalous event is emitted when `disable_rewards=true` causes an early return.

---

### Recommendation

Two complementary fixes:

1. **Move `last_reward_block` write after the `disable_rewards` branch**, so a no-op call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... distribute rewards ...
```

2. **Restrict who may pass `disable_rewards=true`** — e.g., only the attestation contract or a designated consensus role — so the flag cannot be weaponised by an arbitrary caller.

---

### Proof of Concept

1. Staker Alice stakes and is active in the consensus epoch.
2. In block N, attacker (any EOA) calls:
   ```
   staking.update_rewards(alice_address, disable_rewards=true)
   ```
3. `last_reward_block` is set to N; function returns with no rewards distributed.
4. Alice's node operator calls `update_rewards(alice_address, disable_rewards=false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block N's rewards are permanently lost. Repeat every block to drain the entire reward stream. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1449-1452)
```text
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

**File:** src/staking/staking.cairo (L1484-1500)
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
```
