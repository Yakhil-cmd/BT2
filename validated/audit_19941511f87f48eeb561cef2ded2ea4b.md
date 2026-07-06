### Title
Unchecked `approve` Return Value in `Pool::transfer_to_staking_contract` Breaks Delegation for Non-Standard BTC Tokens - (`src/pool/pool.cairo`)

---

### Summary

The `Pool` contract's internal `transfer_to_staking_contract` function calls `token_dispatcher.approve(...)` using the plain `IERC20Dispatcher` without verifying the return value. Every other token interaction in the codebase uses `CheckedIERC20DispatcherTrait` (which asserts the return is `true`), but the `approve` call is left unchecked. For BTC tokens whose `approve` implementation returns `false` or does not return a `bool`, this causes `enter_delegation_pool` and `add_to_delegation_pool` to silently mis-approve and then revert at the downstream `transfer_from`, permanently blocking delegation for that token.

---

### Finding Description

`transfer_to_staking_contract` is the internal helper called by both `enter_delegation_pool` and `add_to_delegation_pool`. It first approves the staking contract to pull funds from the pool, then calls `add_stake_from_pool` which executes the actual `transfer_from`:

```cairo
fn transfer_to_staking_contract(
    self: @ContractState,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
    staker_address: ContractAddress,
) {
    let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
    token_dispatcher
        .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
    staking_pool_dispatcher.add_stake_from_pool(:staker_address, :amount);
}
``` [1](#0-0) 

The `approve` call uses the raw `IERC20DispatcherTrait`, which deserializes the return data as a `bool` but the caller discards it entirely. Contrast this with every transfer and transfer-from call in the same file and in `pool/utils.cairo`, which all go through `CheckedIERC20DispatcherTrait::checked_transfer` / `checked_transfer_from`:

```cairo
// pool/utils.cairo – transfer from delegator uses the checked variant
token_dispatcher
    .checked_transfer_from(
        sender: pool_member, recipient: self_contract, amount: amount.into(),
    );
``` [2](#0-1) 

```cairo
// pool.cairo – exit action also uses the checked variant
token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
``` [3](#0-2) 

The same pattern holds in `staking.cairo`, which imports and uses `CheckedIERC20DispatcherTrait` for all its token movements: [4](#0-3) 

Two failure modes arise from the unchecked `approve`:

1. **Token returns `false` from `approve`** (e.g., a BTC token with approval-race protection that requires resetting to 0 first): the return value is silently discarded, the allowance is never set, and the subsequent `transfer_from` inside `add_stake_from_pool` reverts with an opaque "insufficient allowance" error rather than a meaningful approval-failure message. The delegation is permanently blocked until the token's allowance state is manually reset.

2. **Token does not return a `bool` from `approve`** (non-standard BTC wrapper): `IERC20DispatcherTrait::approve` attempts to deserialize a `bool` from the return data; if the token returns nothing or a different type, the deserialization panics and the call reverts, making `enter_delegation_pool` and `add_to_delegation_pool` completely unusable for that token.

---

### Impact Explanation

Both `enter_delegation_pool` and `add_to_delegation_pool` are the primary entry points for pool members to stake delegated funds. If either failure mode above is triggered, **all delegation to a BTC pool is permanently frozen**: no new members can enter, and existing members cannot increase their stake. This constitutes a **temporary (or permanent) freezing of funds** and breakage of core protocol functionality, matching the allowed High/Medium impact tier.

---

### Likelihood Explanation

The protocol explicitly supports multiple BTC tokens with varying decimal precisions: [5](#0-4) 

BTC-pegged tokens on Starknet (e.g., wrapped BTC bridges) may implement non-standard ERC20 behaviour. The protocol's own codebase already acknowledges this risk by using `CheckedIERC20DispatcherTrait` everywhere else — the `approve` omission is an oversight. Any BTC token whose `approve` returns `false` or omits the return value triggers the bug via a normal, unprivileged `enter_delegation_pool` call.

---

### Recommendation

Replace the raw `approve` call with a checked equivalent that asserts the return value is `true`, consistent with how all other token interactions are handled:

```cairo
// Instead of:
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// Use (if CheckedIERC20DispatcherTrait exposes checked_approve):
token_dispatcher
    .checked_approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
```

If `CheckedIERC20DispatcherTrait` does not yet expose a `checked_approve`, extend it to do so, mirroring the pattern used for `checked_transfer` and `checked_transfer_from`.

---

### Proof of Concept

1. Deploy a BTC token whose `approve` always returns `false`.
2. Register a staker with a BTC pool via `set_open_for_delegation`.
3. As an unprivileged pool member, call `enter_delegation_pool(reward_address, amount)` on the BTC pool.
4. Internally, `transfer_to_staking_contract` calls `token_dispatcher.approve(staking_contract, amount)` — returns `false`, silently ignored.
5. `add_stake_from_pool` is called; the staking contract attempts `transfer_from(pool, staking_contract, amount)` — reverts with "insufficient allowance".
6. The entire `enter_delegation_pool` transaction reverts; no delegation is possible for this BTC token.

### Citations

**File:** src/pool/pool.cairo (L329-331)
```text
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

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

**File:** src/pool/utils.cairo (L124-138)
```text
/// Get token rewards configuration based on address and decimals.
pub(crate) fn get_token_rewards_config(token_address: ContractAddress) -> TokenRewardsConfig {
    if token_address == STRK_TOKEN_ADDRESS {
        STRK_CONFIG
    } else {
        // BTC token.
        let token_dispatcher = IERC20MetadataDispatcher { contract_address: token_address };
        let decimals = token_dispatcher.decimals();
        assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
        TokenRewardsConfig {
            decimals,
            min_for_rewards: 10_u128.pow(decimals.into() - 5),
            base_value: 10_u128.pow(decimals.into() + 5),
        }
    }
```

**File:** src/staking/staking.cairo (L60-60)
```text
    use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```
