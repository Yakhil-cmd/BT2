### Title
Permissionless `update_rewards` Allows Any Caller to Suppress Reward Distribution for Any Staker - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` accepts a `staker_address` parameter and a `disable_rewards` boolean flag but performs no caller identity check. Any address can call it for any staker with `disable_rewards: true`. Because the contract enforces a per-block "already updated" guard (`REWARDS_ALREADY_UPDATED`), a subsequent legitimate call with `disable_rewards: false` will revert. An attacker can front-run every block to permanently prevent any staker from earning consensus rewards.

### Finding Description
The `update_rewards` function in `src/staking/staking.cairo` (exposed via `IStakingRewardsManager`) takes two parameters: `staker_address: ContractAddress` and `disable_rewards: bool`. Unlike `claim_rewards`, which asserts `caller == staker_address || caller == reward_address`, `update_rewards` contains no such check.

When called with `disable_rewards: true`, the function marks the staker's current block as processed without crediting any rewards. The `REWARDS_ALREADY_UPDATED` guard then blocks any further call to `update_rewards` for the same staker in the same block — including a call with `disable_rewards: false` that would have distributed rewards.

The test suite confirms both properties without any `cheat_caller_address` override:

1. The function is callable by any address — the only errors thrown are domain errors (`STAKER_NOT_EXISTS`, `INVALID_STAKER`), never an access-control error: [1](#0-0) 

2. Calling with `disable_rewards: true` sets the "already updated" flag, blocking a subsequent `disable_rewards: false` call in the same block: [2](#0-1) 

3. With `disable_rewards: true` the staker's `unclaimed_rewards_own` is never incremented: [3](#0-2) 

For contrast, `claim_rewards` correctly enforces caller identity: [4](#0-3) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(victim, disable_rewards: true)` every block prevents the victim's `unclaimed_rewards_own` from ever increasing during the consensus rewards phase. Because the guard resets each block, the attacker must repeat the call each block, but Starknet's low gas costs make this economically viable against any high-value staker. The staker's entire future yield stream is frozen with no recourse.

### Likelihood Explanation
**High.** The entry path requires no privilege, no token balance, no prior relationship with the victim, and no special setup. Any public caller can execute the attack immediately after the consensus rewards phase activates. The only cost is per-block gas, which is negligible on Starknet.

### Recommendation
Add a caller identity check to `update_rewards`, mirroring the pattern already used in `claim_rewards`:

```cairo
fn update_rewards(
    ref self: ContractState,
    staker_address: ContractAddress,
    disable_rewards: bool,
) {
    self.general_prerequisites();
    let caller = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    assert!(
        caller == staker_address || caller == staker_info.reward_address,
        "{}",
        Error::CALLER_CANNOT_UPDATE_REWARDS,
    );
    // ... rest of logic
}
```

### Proof of Concept

1. Staker A stakes STRK and the protocol enters the consensus rewards phase.
2. Attacker monitors the chain. Each block, before Staker A (or anyone acting on their behalf) can call `update_rewards(staker_A, disable_rewards: false)`, the attacker calls `update_rewards(staker_A, disable_rewards: true)`.
3. The call succeeds (no access control), marks the block as processed, and distributes zero rewards.
4. Any subsequent call to `update_rewards` for Staker A in that block reverts with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 
5. Staker A's `unclaimed_rewards_own` remains zero indefinitely. All consensus-phase yield is permanently frozen.

### Citations

**File:** src/staking/tests/test.cairo (L3938-3944)
```text
    // Catch INVALID_STAKER - before staker has balance, same epoch of `stake`.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::INVALID_STAKER.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::INVALID_STAKER.describe());
```

**File:** src/staking/tests/test.cairo (L3957-3963)
```text
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```

**File:** src/staking/tests/test.cairo (L3965-3973)
```text
    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```

**File:** src/staking/tests/test.cairo (L4041-4043)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_before);
```

**File:** src/staking/staking.cairo (L415-421)
```text
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```
