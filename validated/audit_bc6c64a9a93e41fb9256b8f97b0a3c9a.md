### Title
Unchecked `approve` Return Value in `transfer_to_staking_contract` Silently Breaks BTC Token Delegation — (`File: src/pool/pool.cairo`)

---

### Summary

`transfer_to_staking_contract` in `src/pool/pool.cairo` calls the plain `IERC20Dispatcher.approve()` and discards its return value. Every other token operation in the codebase uses the `CheckedIERC20DispatcherTrait` variants (`checked_transfer_from`, `checked_transfer`), which assert the return value. If a supported BTC token's `approve` returns `false`, the allowance is never set, the subsequent `checked_transfer_from` inside `add_stake_from_pool` reverts, and all delegation into that pool is permanently blocked.

---

### Finding Description

`pool.cairo` imports `CheckedIERC20DispatcherTrait` at line 47 but does not use it for the approval step inside `transfer_to_staking_contract`:

```cairo
// src/pool/pool.cairo:674-681
// Approve staking contract to transfer funds from the pool.
let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// Notify the staking contract of the new delegated stake.
staking_pool_dispatcher.add_stake_from_pool(:staker_address, :amount);
```

The return value of `.approve()` is silently discarded. `add_stake_from_pool` in `staking.cairo` then calls `checked_transfer_from`:

```cairo
// src/staking/staking.cairo:1031-1034
token_dispatcher
    .checked_transfer_from(
        sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
    );
```

`checked_transfer_from` asserts the transfer succeeds. If the prior `approve` returned `false` (allowance not set), this assertion fails and the entire transaction reverts.

By contrast, every other token movement in the codebase uses the checked variants:
- `transfer_from_delegator` in `src/pool/utils.cairo:24-27` uses `checked_transfer_from`
- `send_rewards_to_staker` in `src/staking/staking.cairo:1625` uses `checked_transfer`
- `transfer_to_pools_when_unstake` in `src/staking/staking.cairo:1676-1680` uses `checked_transfer`

`transfer_to_staking_contract` is called from two public entry points:
- `enter_delegation_pool` (via the flow at `pool.cairo:~190`)
- `add_to_delegation_pool` at `pool.cairo:239`

Both are callable by any unprivileged delegator.

---

### Impact Explanation

If a BTC token whose `approve` returns `false` is active in the protocol, every call to `enter_delegation_pool` or `add_to_delegation_pool` for that token will revert at the `checked_transfer_from` step inside `add_stake_from_pool`. Delegators are unable to stake their BTC tokens into any pool, and any funds already approved by the delegator (pre-condition for calling these functions) are locked in limbo until the protocol is patched. This matches the **Medium: griefing with no profit motive but damage to users or protocol** impact category.

---

### Likelihood Explanation

The protocol explicitly supports arbitrary BTC tokens added via `token_admin`. The `add_token` path in `staking.cairo` only validates decimals, not that `approve` conforms to the checked interface. A non-standard token (one whose `approve` returns `false` on certain conditions, e.g., a token with a blocklist or a fee-on-transfer variant) would trigger this silently. The entry path is fully reachable by any unprivileged delegator once such a token is active.

---

### Recommendation

Replace the plain `.approve()` call with the checked variant, consistent with every other token operation in the codebase:

```cairo
// Before (pool.cairo:676-677)
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// After
token_dispatcher
    .checked_approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
```

If `CheckedIERC20DispatcherTrait` does not yet expose `checked_approve`, add it to `starkware_utils::erc20::erc20_utils` following the same pattern as `checked_transfer` and `checked_transfer_from`.

---

### Proof of Concept

1. Token admin adds a BTC token whose `approve` returns `false` (e.g., a token with a transfer-restriction mechanism).
2. Delegator calls `enter_delegation_pool` or `add_to_delegation_pool` with that token.
3. `transfer_from_delegator` succeeds (tokens move from delegator → pool).
4. `transfer_to_staking_contract` calls `.approve()` → returns `false`, silently ignored.
5. `add_stake_from_pool` calls `checked_transfer_from` → allowance is 0 → assertion fails → transaction reverts.
6. Delegator's tokens are returned (revert), but the operation is permanently blocked for that token, making the pool unusable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L47-47)
```text
    use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```

**File:** src/pool/pool.cairo (L235-239)
```text
            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L668-682)
```text
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

            // Notify the staking contract of the new delegated stake.
            // This will complete the fund transfer to the staking contract.
            staking_pool_dispatcher.add_stake_from_pool(:staker_address, :amount);
        }
```

**File:** src/pool/utils.cairo (L20-28)
```text
pub(crate) fn transfer_from_delegator(
    pool_member: ContractAddress, amount: Amount, token_dispatcher: IERC20Dispatcher,
) {
    let self_contract = get_contract_address();
    token_dispatcher
        .checked_transfer_from(
            sender: pool_member, recipient: self_contract, amount: amount.into(),
        );
}
```

**File:** src/staking/staking.cairo (L1028-1034)
```text
            // Transfer funds from the pool contract to the staking contract.
            // Sufficient approval is a pre-condition.
            let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
            token_dispatcher
                .checked_transfer_from(
                    sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
                );
```
