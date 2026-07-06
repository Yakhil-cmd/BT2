### Title
Unrestricted `disable_rewards=true` Call Permanently Freezes Per-Block Yield for All Stakers — (File: src/staking/staking.cairo)

### Summary
The public `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards` boolean. When set to `true`, the function still writes `last_reward_block = current_block_number` but returns before distributing any rewards. Because the contract enforces a strict one-call-per-block invariant (`current_block_number > last_reward_block`), any unprivileged caller can permanently consume a block's reward slot without distributing rewards, causing all stakers to lose that block's yield forever.

### Finding Description
`update_rewards` is part of the public `IStakingRewardsManager` interface. It contains no caller-identity check beyond `general_prerequisites()` (a pause guard). The relevant logic is:

```
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← slot consumed unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← rewards skipped, slot already gone
}
``` [1](#0-0) 

The one-call-per-block guard is:

```
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

Once `last_reward_block` is set to block N, every subsequent call in block N reverts. There is no recovery path: the rewards that would have been distributed in block N are permanently unclaimable.

The analog to the Taiko report is direct: in Taiko, `lastSyncedBlock` was not updated at the correct granularity, causing the gas-issuance accounting variable to diverge from reality. Here, `last_reward_block` is updated at the correct granularity (every block) but is updated *before* the reward distribution guard, so an adversary can advance the accounting pointer without triggering the corresponding reward payout — the same class of state-variable/accounting desynchronisation.

### Impact Explanation
Every block in the V3 consensus-rewards regime is worth `yearly_mint × avg_block_duration / (BLOCK_DURATION_SCALE × SECONDS_IN_YEAR)` STRK (plus BTC rewards). [3](#0-2) 

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block causes every staker and every pool member to permanently lose that block's yield. Repeated across many blocks this constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

### Likelihood Explanation
- `update_rewards` is a fully public function with no role or caller restriction. [4](#0-3) 
- The attacker only needs to know one active staker address with non-zero balance, which is trivially discoverable from on-chain events (`NewStaker`). [5](#0-4) 
- The gas cost per block is a single contract call — economically viable for a motivated griever.
- No privileged access, no leaked key, no bridge compromise required.

### Recommendation
Move the `last_reward_block` write to *after* the `disable_rewards` early-return, or add an access-control check (e.g., only the staker themselves or an authorised keeper may call with `disable_rewards = true`). Alternatively, separate the "tick the block counter" responsibility from the "distribute rewards" responsibility into two distinct functions with appropriate guards.

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes any active staker address `S` with non-zero STRK balance.
3. At the start of every new block N, attacker submits:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function writes `last_reward_block = N` and returns early — no rewards distributed. [1](#0-0) 
5. Any legitimate call to `update_rewards` in block N now reverts with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 
6. All stakers and pool members receive zero block rewards for block N; the yield is permanently lost.
7. Repeating step 3 every block freezes all consensus-regime yield indefinitely.

### Citations

**File:** src/staking/staking.cairo (L1354-1358)
```text
            assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
            self.btc_tokens.write(token_address, (STARTING_EPOCH, false));
            self.token_decimals.write(token_address, decimals);
            // Initialize the token total stake trace.
            self
```

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

**File:** src/reward_supplier/reward_supplier.cairo (L178-183)
```text
            let total_rewards = mul_wide_and_div(
                lhs: yearly_mint,
                rhs: avg_block_duration.into(),
                div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
```
