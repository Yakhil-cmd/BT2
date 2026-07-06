### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is callable by any unprivileged address. Because it writes to the global `last_reward_block` storage slot before checking `disable_rewards`, an attacker can call it with `disable_rewards: true` in every block, consuming the per-block reward slot without distributing any rewards. This permanently prevents all stakers from accumulating consensus-phase unclaimed yield.

### Finding Description
`update_rewards` is exposed via `IStakingRewardsManager` with no role-based access control. Its only caller guard is `general_prerequisites`, which only asserts the contract is unpaused and the caller is non-zero.

The function's critical sequence is:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← exits without distributing
}
``` [1](#0-0) 

The global `last_reward_block` is written unconditionally before the early-return guard. Any subsequent call in the same block fails with `REWARDS_ALREADY_UPDATED`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

The attacker only needs to supply any currently-active staker address with non-zero epoch balance (both are publicly readable on-chain).

### Impact Explanation
In the consensus rewards phase (after `consensus_rewards_first_epoch` is set), every block is a reward opportunity for one staker. By calling `update_rewards(any_valid_staker, disable_rewards: true)` in every block, an attacker:

1. Writes `last_reward_block = current_block`.
2. Returns early — no `_update_rewards` is executed, no `unclaimed_rewards_own` is incremented, no pool rewards are forwarded.
3. Blocks the legitimate consensus-system call for that block.

Repeated across all blocks, this permanently freezes all unclaimed consensus yield for every staker and every delegation pool member. This maps to **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- No stake, no role, no special permission is required — only gas.
- The attacker address just needs to be non-zero and the contract unpaused.
- A valid staker address to pass the `is_staker_active` / non-zero balance checks is trivially obtained from on-chain events (`NewStaker`).
- The cost is one cheap transaction per block; the attacker gains nothing financially but inflicts unbounded yield loss on all participants.

### Recommendation
Restrict `update_rewards` to the authorized consensus caller. The simplest fix is to add a role check (e.g., `only_rewards_manager` or `only_block_proposer`) at the top of the function, analogous to how `update_rewards_from_attestation_contract` restricts itself to the attestation contract:

```cairo
fn assert_caller_is_attestation_contract(self: @ContractState) {
    assert!(
        get_caller_address() == self.attestation_contract.read(),
        "{}",
        Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
    );
}
``` [3](#0-2) 

A dedicated `rewards_manager_address` storage slot (or a new role in `RolesComponent`) should be introduced, and `update_rewards` should assert `get_caller_address() == rewards_manager_address` before proceeding.

### Proof of Concept

```
// Pseudocode — executable on any Starknet fork after consensus_rewards_first_epoch is set

// 1. Read any active staker address from on-chain NewStaker events.
let victim_staker = <any active staker with non-zero epoch balance>;

// 2. In every block, submit this transaction before the legitimate consensus call:
staking_contract.update_rewards(
    staker_address: victim_staker,
    disable_rewards: true,   // ← no rewards distributed
);
// last_reward_block is now set to current_block.

// 3. The legitimate consensus system attempts:
staking_contract.update_rewards(staker_address: proposer, disable_rewards: false);
// → panics: "Rewards already updated for this block"

// 4. Repeat every block → zero consensus rewards ever accumulate for any staker.
```

### Citations

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```
