### Title
Permissionless `update_rewards` with Unguarded `disable_rewards` Parameter Allows Anyone to Permanently Freeze All Stakers' Unclaimed Yield - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` is fully permissionless and accepts a caller-controlled `disable_rewards: bool` parameter. Any external actor can invoke it with `disable_rewards: true` for any valid staker address. Because the function unconditionally writes the current block number to the **global** `last_reward_block` storage slot before checking `disable_rewards`, a single call per block is sufficient to consume the one-per-block reward slot for the entire protocol without distributing any rewards. An attacker who front-runs every block with this call permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is exposed as a public ABI function under `IStakingRewardsManager`:

```cairo
// src/staking/staking.cairo  lines 1448-1507
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only: not-paused + caller != 0
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        // *** last_reward_block is written BEFORE the disable_rewards branch ***
        self.last_reward_block.write(current_block_number);

        if disable_rewards || self.is_pre_consensus() {
            return;                                            // exits with NO rewards distributed
        }
        ...
    }
}
```

`general_prerequisites` imposes no caller restriction:

```cairo
// src/staking/staking.cairo  lines 1793-1797
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

`last_reward_block` is a **single global slot** (not per-staker):

```cairo
// src/staking/staking.cairo  line 187
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

The gate that prevents double-processing is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is global and is written before the `disable_rewards` branch, a single call per block with `disable_rewards: true` exhausts the entire block's reward slot for every staker in the protocol.

**Attack path:**

1. Attacker monitors the mempool / block production.
2. At the start of every block, attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number; the function returns early with no rewards distributed.
4. Any subsequent call in the same block (by the legitimate staker or the consensus mechanism) reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block permanently prevents all stakers from accumulating consensus rewards.

The attacker needs only a valid active staker address (publicly readable from on-chain events) and enough gas per block.

---

### Impact Explanation

`update_rewards` is the sole mechanism through which consensus-era block rewards are distributed to stakers and their delegation pools. Blocking it every block means:

- `staker_info.unclaimed_rewards_own` never increases for any staker.
- Pool rewards are never pushed to delegation pools.
- All accumulated yield is permanently frozen at its current value.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is fully permissionless; no privileged key or special role is required.
- The attacker only needs to know one valid active staker address, which is trivially obtained from `NewStaker` events.
- The cost is one Starknet transaction per block (~3 seconds). Starknet transaction fees are low, making sustained griefing economically viable.
- No profit motive is required; the attack is pure griefing.

---

### Recommendation

Restrict who may supply `disable_rewards: true`. The simplest fix is to require that the caller is either the staker's registered operational address or the staker address itself when `disable_rewards` is `true`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    if disable_rewards {
        let staker_info = self.internal_staker_info(:staker_address);
        let caller = get_caller_address();
        assert!(
            caller == staker_address || caller == staker_info.operational_address,
            "{}",
            Error::UNAUTHORIZED_DISABLE_REWARDS,
        );
    }
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus / transition logic internally.

---

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(alice_staker, disable_rewards=true)
    → last_reward_block = N
    → returns early, no rewards distributed

  Alice (or consensus) calls: staking.update_rewards(alice_staker, disable_rewards=false)
    → assert!(N > N) FAILS → reverts with REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker repeats the same call.
  → last_reward_block = N+1, no rewards distributed again.

Result: Alice's unclaimed_rewards_own never increases.
        All delegation pool rewards are permanently frozen.
```

The attacker requires:
- One valid active staker address (public from events).
- Gas for one transaction per block (~3 s on Starknet).
- No privileged access, no leaked keys, no external dependency.