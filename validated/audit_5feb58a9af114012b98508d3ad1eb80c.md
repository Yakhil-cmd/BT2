### Title
Overestimated `unclaimed_rewards` in `request_funds` Causes Unnecessary L1 Mint Requests — (File: src/reward_supplier/reward_supplier.cairo)

### Summary
In `_update_rewards` (`src/staking/staking.cairo`), `update_unclaimed_rewards_from_staking_contract` is called with `staker_rewards + total_pools_rewards`, which immediately triggers `request_funds` using an inflated `unclaimed_rewards` value. The `total_pools_rewards` portion is claimed back in the very next call (`claim_from_reward_supplier`), but `request_funds` has already used the over-estimated debit to decide how many L1 mint messages to send. This is a direct analog to the reported pattern: a cumulative total that is about to be zeroed out is still included in a threshold calculation, causing over-estimation.

---

### Finding Description

In `_update_rewards` the sequence is:

```cairo
// Step 1 — inflates unclaimed_rewards by staker_rewards + total_pools_rewards,
// then immediately calls request_funds with that inflated value.
reward_supplier_dispatcher
    .update_unclaimed_rewards_from_staking_contract(
        rewards: staker_rewards + total_pools_rewards,   // ← pool rewards included
    );

// Step 2 — immediately claims total_pools_rewards back out.
claim_from_reward_supplier(
    :reward_supplier_dispatcher,
    amount: total_pools_rewards,
    token_dispatcher: strk_token_dispatcher(),
);
```

Inside `update_unclaimed_rewards_from_staking_contract`:

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
self.unclaimed_rewards.write(unclaimed_rewards);
self.request_funds(:unclaimed_rewards);   // ← called before pool rewards are claimed
```

And `request_funds` computes:

```cairo
let credit = balance + l1_pending_requested_amount;
let debit  = unclaimed_rewards;           // ← still includes total_pools_rewards
if credit < debit + threshold {
    // sends L1 mint messages and increases l1_pending_requested_amount
}
```

By the time `claim_from_reward_supplier` executes, `unclaimed_rewards` is reduced by `total_pools_rewards` and the contract's STRK balance is also reduced by `total_pools_rewards`. However, `request_funds` has already fired with a debit that is `total_pools_rewards` higher than the true steady-state debit, potentially sending one or more extra L1 mint messages per reward update.

---

### Impact Explanation

Every reward update for a staker that has at least one active pool over-estimates the required L1 mint by `total_pools_rewards`. Concretely:

1. **Unbounded gas consumption on L1** — each spurious `send_message_to_l1_syscall` call costs L1 gas. Because reward updates happen continuously (every block in V3 consensus mode, every epoch in V2), the extra messages accumulate without bound.
2. **Protocol over-minting** — each extra message causes the L1 `RewardSupplier` to call `MintManager.mintRequest`, minting STRK tokens that are not yet needed. The excess tokens accumulate in the L2 reward supplier contract, inflating the circulating supply ahead of schedule and diluting existing STRK holders.

This matches the allowed Medium impact: *"Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption."*

---

### Likelihood Explanation

The condition is triggered on **every** call to `update_rewards_from_attestation_contract` (V2) or `update_rewards` (V3) for any staker that has at least one pool with a non-zero balance. In a live network with many stakers and delegators this fires on every block (V3) or every epoch (V2), making the likelihood **High**.

---

### Recommendation

Move the `request_funds` call to after `claim_from_reward_supplier` has executed, so the debit reflects the true residual `unclaimed_rewards`. One clean approach is to split the accounting:

1. Call `update_unclaimed_rewards_from_staking_contract(staker_rewards)` — only the portion that stays in the reward supplier.
2. Transfer pool rewards directly without routing through `unclaimed_rewards`, or call a separate function that does not trigger `request_funds`.

Alternatively, pass only `staker_rewards` as the `rewards` argument and handle pool-reward funding through a separate path that does not inflate the debit seen by `request_funds`.

---

### Proof of Concept

**State before a reward update:**
- `unclaimed_rewards = U`
- `balance = B`
- `l1_pending_requested_amount = P`
- `credit = B + P`, `threshold = T`

**Step 1 — `update_unclaimed_rewards_from_staking_contract(staker_rewards + pool_rewards)`:**
- `unclaimed_rewards` becomes `U + staker_rewards + pool_rewards`
- `request_funds` fires with `debit = U + staker_rewards + pool_rewards`
- If `B + P < U + staker_rewards + pool_rewards + T`, extra L1 messages are sent and `l1_pending_requested_amount` grows by `ceil((debit + T − credit) / base_mint_amount) * base_mint_amount`

**Step 2 — `claim_from_reward_supplier(pool_rewards)`:**
- `unclaimed_rewards` drops back to `U + staker_rewards`
- `balance` drops by `pool_rewards`

**Net effect:** `request_funds` was evaluated against a debit that was `pool_rewards` too high. The extra L1 messages have already been dispatched. Over N reward updates the total spurious minting is approximately `N * pool_rewards`, growing without bound as the protocol operates normally.