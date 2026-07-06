### Title
Unchecked `approve()` Return Value in Pool's `transfer_to_staking_contract` Permanently Breaks Delegation for Non-Reverting ERC20 Tokens - (File: src/pool/pool.cairo)

### Summary

`Pool::transfer_to_staking_contract` calls `token_dispatcher.approve(...)` using the raw `IERC20DispatcherTrait` without checking the return value. Every other token operation in the codebase uses the `CheckedIERC20DispatcherTrait` wrappers (`checked_transfer`, `checked_transfer_from`). For any supported token whose `approve` silently returns `false` instead of reverting, the subsequent `checked_transfer_from` inside `add_stake_from_pool` will always revert because the allowance was never set, permanently preventing any delegator from entering or adding to the pool for that token.

### Finding Description

In `src/pool/pool.cairo`, the private helper `transfer_to_staking_contract` (lines 668–682) is responsible for approving the staking contract to pull funds from the pool and then notifying it:

```cairo
fn transfer_to_staking_contract(
    self: @ContractState,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
    staker_address: ContractAddress,
) {
    // Approve staking contract to transfer funds from the pool.
    let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
    token_dispatcher
        .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
    // ...
    staking_pool_dispatcher.add_stake_from_pool(:staker_address, :amount);
}
```

The `approve` call uses the raw `IERC20DispatcherTrait`, whose return value (`bool`) is silently discarded. The `CheckedIERC20DispatcherTrait` is imported at line 47 of `pool.cairo` but is not applied to this call.

`add_stake_from_pool` in `staking.cairo` (lines 1031–1034) then calls `checked_transfer_from(sender: pool_contract, ...)`, which **will revert** if the allowance is zero. For a token that returns `false` from `approve` without reverting, the allowance is never set, so every call to `enter_delegation_pool` or `add_to_delegation_pool` for that token will always revert at the `checked_transfer_from` step.

The call chain is:
1. `enter_delegation_pool` / `add_to_delegation_pool` → `transfer_from_delegator` (uses `checked_transfer_from` — safe)
2. → `transfer_to_staking_contract` → **unchecked** `approve` (silent failure possible)
3. → `add_stake_from_pool` → `checked_transfer_from` → **reverts** because allowance = 0

The entire transaction reverts atomically, so delegator funds are not directly stolen. However, the pool becomes permanently unusable for any token with non-reverting `approve` failures.

### Impact Explanation

For any token supported by the multi-token staking system (e.g., a future BTC-pegged token) whose `approve` implementation silently returns `false` rather than reverting, the delegation pool for that staker/token pair is permanently broken. No delegator can ever successfully call `enter_delegation_pool` or `add_to_delegation_pool`. This constitutes **griefing with damage to users and the protocol** — delegators cannot participate, and the staker's pool is rendered inoperable without any recourse short of a contract upgrade. This matches the **Medium** allowed impact: *Griefing with no profit motive but damage to users or protocol*.

### Likelihood Explanation

The STRK token uses OpenZeppelin's Cairo ERC20 which always reverts on failure, so STRK pools are unaffected. However, the protocol explicitly supports multi-token staking (BTC integration). Any whitelisted token that follows the older ERC20 pattern of returning `false` on failure (rather than reverting) would trigger this bug. The inconsistency is a latent defect that becomes exploitable as new tokens are added.

### Recommendation

Replace the raw `.approve(...)` call with a checked variant, consistent with every other token operation in the codebase:

```cairo
// Before (unchecked):
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// After (checked — mirrors checked_transfer_from usage elsewhere):
token_dispatcher
    .checked_approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
```

If `CheckedIERC20DispatcherTrait` does not yet expose a `checked_approve`, add one following the same pattern as `checked_transfer` and `checked_transfer_from`.

### Proof of Concept

1. A token `T` is whitelisted for multi-token staking. `T.approve()` returns `false` silently on failure (e.g., due to a non-standard implementation or a frozen approval state).
2. Delegator calls `Pool::enter_delegation_pool(reward_address, amount)`.
3. `transfer_from_delegator` succeeds — `amount` of `T` moves from delegator to pool.
4. `transfer_to_staking_contract` calls `token_dispatcher.approve(staking_contract, amount)` — returns `false`, no revert, allowance remains 0.
5. `add_stake_from_pool` calls `checked_transfer_from(sender: pool_contract, ...)` — reverts because allowance is 0.
6. Entire transaction reverts. Delegation is impossible for all delegators on this pool.

Root cause line: [1](#0-0) 

Callers that trigger this path: [2](#0-1) [3](#0-2) 

The `CheckedIERC20DispatcherTrait` is imported but unused for `approve`: [4](#0-3) 

Contrast with the safe pattern used everywhere else: [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L47-47)
```text
    use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```

**File:** src/pool/pool.cairo (L196-199)
```text
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L235-239)
```text
            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L676-677)
```text
            token_dispatcher
                .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
```

**File:** src/pool/utils.cairo (L24-27)
```text
    token_dispatcher
        .checked_transfer_from(
            sender: pool_member, recipient: self_contract, amount: amount.into(),
        );
```

**File:** src/staking/staking.cairo (L1031-1034)
```text
            token_dispatcher
                .checked_transfer_from(
                    sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
                );
```
