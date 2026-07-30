### Title
Unguarded `rewards_pool` split in `redeem_fungible_staked_sui` can abort/permanently lock FungibleStakedSui redemptions when shared reward accounting diverges - (File: `crates/sui-framework/packages/sui-system/sources/staking_pool.move`)

### Summary
The external report's root cause is that two independent claim types (vault-staker yield and game-player rewards) draw from one shared reward pool, computed independently of each other, so the sum of claims can exceed the actual pool balance and the "last" claimant's withdrawal reverts. Sui's `StakingPool` has a structurally identical shared-pool pattern: `StakedSui` withdrawals and `FungibleStakedSui` redemptions both draw proportional "rewards" from the single `pool.rewards_pool` balance, computed via independent, only loosely-reconciled accounting (`sui_balance`/`pool_token_balance` exchange rate vs. `FungibleStakedSuiData.total_supply`/`principal`).

### Finding Description
`request_withdraw_stake` → `withdraw_rewards` computes a proportional reward amount from the epoch's `PoolTokenExchangeRate` and then explicitly clamps it against the real pool balance: [1](#0-0) 

The inline comment acknowledges the underlying issue is already known and unresolved: *"This may happen when we are withdrawing everything from the pool and the rewards pool balance may be less than reward_withdraw_amount. TODO: FIGURE OUT EXACTLY WHY THIS CAN HAPPEN."*

By contrast, `redeem_fungible_staked_sui`, which services the second, independently-tracked claim type (`FungibleStakedSuiData`), computes its reward share via `calculate_fungible_staked_sui_withdraw_amount` and then splits directly from `pool.rewards_pool` with **no clamp**: [2](#0-1) 

`calculate_fungible_staked_sui_withdraw_amount` only asserts that `principal_withdraw_amount + rewards_withdraw_amount <= expected_sui_amount` (an internal proportionality check), it does **not** validate against the actual current `pool.rewards_pool.value()`: [3](#0-2) 

Both code paths draw from the same `rewards_pool: Balance<SUI>` field, but only one (`withdraw_rewards`, used for plain `StakedSui`) has a defensive `.min()` clamp against underflow/abort. The `FungibleStakedSui` path has no equivalent safeguard, so if the pool's actual `rewards_pool` balance is smaller than what the exchange-rate-derived math predicts for the remaining fungible-stake holders (the exact scenario the codebase's own TODO comment says "can happen"), `balance::split` will abort the transaction because it requires the balance to hold at least the requested amount.

### Impact Explanation
If `redeem_fungible_staked_sui` is called by a `FungibleStakedSui` holder at a point where `pool.rewards_pool.value() < rewards_amount` computed from the exchange rate, the transaction aborts. Since the underlying accounting condition that caused the shortfall does not self-correct (the exchange-rate table entry for that epoch is immutable and `pool.rewards_pool` will not be replenished until the next epoch's `deposit_rewards`), the holder may be unable to redeem within the current epoch, and if the shortfall persists across the object's usable window this constitutes the "permanent fund lock" High-severity impact category (unable to convert a `FungibleStakedSui` object back into `SUI`/underlying stake). This affects ordinary, unprivileged stakers using the standard `convert_to_fungible_staked_sui` / `redeem_fungible_staked_sui` flow reachable from any public transaction.

### Likelihood Explanation
Medium-to-low confidence on exact triggering conditions: the Sui team's own `TODO: FIGURE OUT EXACTLY WHY THIS CAN HAPPEN` comment confirms the underflow scenario is a real, previously-observed condition in the `withdraw_rewards` path, but I could not fully trace, within the available index, the exact sequence of state transitions (e.g., interleaving of `process_pending_stake_withdraw`, `UnderflowSuiBalance` handling, and multiple same-epoch withdrawals) that produces the discrepancy, nor could I confirm the exact abort behavior of `balance::split` in `sui-framework/sources/balance.move` (its source was not resolvable via the search index). The asymmetry between the two withdrawal paths (one guarded, one not) is concrete and verifiable in the code shown above, but whether it is practically triggerable to the point of a genuine, reproducible High-impact fund lock — versus being an extremely rare edge case already effectively mitigated by the exchange-rate design — remains unconfirmed without deeper trace-level testing (ideally in a Devin session with full repo/tooling access) of `process_pending_stake`, `process_pending_stake_withdraw`, and the interaction between `sui_balance`/`pool_token_balance` and `FungibleStakedSuiData` bookkeeping across an epoch with concurrent `StakedSui` and `FungibleStakedSui` claims.

### Recommendation
Apply the same defensive clamp used in `withdraw_rewards` to `redeem_fungible_staked_sui` — i.e., `rewards_amount = rewards_amount.min(pool.rewards_pool.value())` before calling `split` — or, more robustly, reconcile the `FungibleStakedSuiData` accounting against `pool.rewards_pool`/`pool.sui_balance` fully so that the sum of all claims (regular `StakedSui` and `FungibleStakedSui`) can never exceed the actual pool balance, rather than only patching the symptom in one of the two withdrawal paths.

### Proof of Concept
Could not construct a concrete, verified end-to-end PoC transaction sequence with the tools available (no ability to run Move tests or trace live state in this session). The finding is based on static code comparison between `withdraw_rewards` (guarded) and `redeem_fungible_staked_sui` (unguarded), plus the codebase's own acknowledgement (`EInvariantFailure`/TODO comment) that the underlying exchange-rate-vs-actual-balance divergence is a known, real occurrence. A background Devin session with Move test tooling would be needed to construct a minimal repro (e.g., stake via both `StakedSui` and `convert_to_fungible_staked_sui` into the same pool, drive several epochs of reward deposits and interleaved withdrawals, and check whether `redeem_fungible_staked_sui` can be made to abort due to `pool.rewards_pool` underflow) before this can be confirmed as exploitable in practice.

### Citations

**File:** crates/sui-framework/packages/sui-system/sources/staking_pool.move (L195-227)
```text
public(package) fun redeem_fungible_staked_sui(
    pool: &mut StakingPool,
    fungible_staked_sui: FungibleStakedSui,
    ctx: &TxContext,
): Balance<SUI> {
    let FungibleStakedSui { id, pool_id, value } = fungible_staked_sui;
    assert!(pool_id == object::id(pool), EWrongPool);

    id.delete();

    let latest_exchange_rate = pool.pool_token_exchange_rate_at_epoch(ctx.epoch());
    let fungible_staked_sui_data: &mut FungibleStakedSuiData =
        &mut pool.extra_fields[FungibleStakedSuiDataKey {}];

    let (
        principal_amount,
        rewards_amount,
    ) = latest_exchange_rate.calculate_fungible_staked_sui_withdraw_amount(
        value,
        fungible_staked_sui_data.principal.value(),
        fungible_staked_sui_data.total_supply,
    );

    fungible_staked_sui_data.total_supply = fungible_staked_sui_data.total_supply - value;

    let mut sui_out = fungible_staked_sui_data.principal.split(principal_amount);
    sui_out.join(pool.rewards_pool.split(rewards_amount));

    pool.pending_total_sui_withdraw = pool.pending_total_sui_withdraw + sui_out.value();
    pool.pending_pool_token_withdraw = pool.pending_pool_token_withdraw + value;

    sui_out
}
```

**File:** crates/sui-framework/packages/sui-system/sources/staking_pool.move (L231-271)
```text
fun calculate_fungible_staked_sui_withdraw_amount(
    latest_exchange_rate: PoolTokenExchangeRate,
    fungible_staked_sui_value: u64,
    fungible_staked_sui_data_principal_amount: u64, // fungible_staked_sui_data.principal.value()
    fungible_staked_sui_data_total_supply: u64, // fungible_staked_sui_data.total_supply
): (u64, u64) {
    // 1. if the entire FungibleStakedSuiData supply is redeemed, how much sui should we receive?
    let total_sui_amount = latest_exchange_rate.get_sui_amount(
        fungible_staked_sui_data_total_supply,
    );

    // min with total_sui_amount to prevent underflow
    let fungible_staked_sui_data_principal_amount = fungible_staked_sui_data_principal_amount.min(
        total_sui_amount,
    );

    // 2. how much do we need to withdraw from the rewards pool?
    let total_rewards = total_sui_amount - fungible_staked_sui_data_principal_amount;

    // 3. proportionally withdraw from both wrt the fungible_staked_sui_value.
    let principal_withdraw_amount = mul_div!(
        fungible_staked_sui_value,
        fungible_staked_sui_data_principal_amount,
        fungible_staked_sui_data_total_supply,
    );

    let rewards_withdraw_amount = mul_div!(
        fungible_staked_sui_value,
        total_rewards,
        fungible_staked_sui_data_total_supply,
    );

    // invariant check, just in case
    let expected_sui_amount = latest_exchange_rate.get_sui_amount(fungible_staked_sui_value);
    assert!(
        principal_withdraw_amount + rewards_withdraw_amount <= expected_sui_amount,
        EInvariantFailure,
    );

    (principal_withdraw_amount, rewards_withdraw_amount)
}
```

**File:** crates/sui-framework/packages/sui-system/sources/staking_pool.move (L424-441)
```text
fun withdraw_rewards(
    pool: &mut StakingPool,
    principal_withdraw_amount: u64,
    pool_token_withdraw_amount: u64,
    epoch: u64,
): Balance<SUI> {
    let exchange_rate = pool.pool_token_exchange_rate_at_epoch(epoch);
    let total_sui_withdraw_amount = exchange_rate.get_sui_amount(pool_token_withdraw_amount);
    let mut reward_withdraw_amount = if (total_sui_withdraw_amount >= principal_withdraw_amount) {
        total_sui_withdraw_amount - principal_withdraw_amount
    } else 0;

    // This may happen when we are withdrawing everything from the pool and
    // the rewards pool balance may be less than reward_withdraw_amount.
    // TODO: FIGURE OUT EXACTLY WHY THIS CAN HAPPEN.
    reward_withdraw_amount = reward_withdraw_amount.min(pool.rewards_pool.value());
    pool.rewards_pool.split(reward_withdraw_amount)
}
```
