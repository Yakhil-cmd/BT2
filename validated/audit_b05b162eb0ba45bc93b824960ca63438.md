Based on my investigation of the actual implementation, this is a **real vulnerability**.

## Key Findings

### 1. No Access Control on `update_rewards`

The spec at `docs/spec.md` line 1645 states access control is **"Only starkware sequencer"**, but the implementation contains no such check: [1](#0-0) 

`general_prerequisites()` only checks:
- Contract is not paused
- Caller is not the zero address

There is no sequencer role check, no `only_sequencer()` call, and no caller identity validation anywhere in `update_rewards`.

### 2. `last_reward_block` Is a Global Variable [2](#0-1) 

It is accessed as `self.last_reward_block.read()` with no per-staker key — it is a single global slot for the entire contract. Only **one** `update_rewards` call can succeed per block, for any staker.

### 3. `disable_rewards: true` Consumes the Block Slot Without Distributing Rewards [3](#0-2) 

The `last_reward_block` is written **before** the `disable_rewards` check. So calling with `disable_rewards: true` permanently marks the block as "already updated" while distributing zero rewards.

---

### Title
Public `update_rewards` Lacks Caller Restriction, Allowing Any Address to Suppress Block Rewards via `disable_rewards: true` — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is callable by any non-zero address. A global `last_reward_block` gate allows only one call per block. An attacker who calls first with `disable_rewards: true` consumes the block's reward slot without distributing rewards, permanently discarding that block's yield for all stakers.

### Finding Description
The spec mandates "Only starkware sequencer" access control for `update_rewards`, but `general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. [4](#0-3)  Any EOA or contract can call `update_rewards(any_valid_active_staker, disable_rewards: true)`. The function writes `last_reward_block = current_block` at line 1485 before returning early at line 1487–1488. Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`. [5](#0-4)  The block's rewards are permanently lost.

### Impact Explanation
Every block where consensus rewards are active, an attacker can front-run the sequencer's `update_rewards` call with `disable_rewards: true`, permanently discarding that block's STRK yield for all stakers and delegators. This is repeatable every block at negligible cost (only gas). Impact: **Permanent freezing of unclaimed yield** (High).

### Likelihood Explanation
The function is fully public with no role gate. The attack requires only a valid active staker address (publicly discoverable on-chain) and a transaction submitted before the sequencer's. On Starknet, the sequencer ordering is deterministic but the mempool is observable. The attack is cheap, repeatable, and requires no capital.

### Recommendation
Add a sequencer-only access check to `update_rewards`, consistent with the spec. For example:
```rust
fn update_rewards(...) {
    self.roles.only_sequencer(); // or equivalent caller check
    self.general_prerequisites();
    ...
}
```

### Proof of Concept
1. Deploy with two active stakers, consensus rewards active.
2. In block N, attacker calls `update_rewards(staker_A, disable_rewards: true)` — succeeds, sets `last_reward_block = N`, distributes zero rewards.
3. Sequencer calls `update_rewards(staker_A, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
4. Block N's rewards are permanently lost.
5. Repeat every block. Cumulative rewards observed = 0 vs. expected model = N × block_reward. [3](#0-2)

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

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
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
