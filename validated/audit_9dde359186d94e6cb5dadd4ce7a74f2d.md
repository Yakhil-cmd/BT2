### Title
Missing Return Value Check on `ERC20.approve()` in `transfer_to_staking_contract` - (File: src/pool/pool.cairo)

### Summary
The `transfer_to_staking_contract` internal function in `Pool` calls `token_dispatcher.approve(...)` but silently discards the `bool` return value. Every other token operation in the same codebase uses the `CheckedIERC20DispatcherTrait` wrappers (`checked_transfer`, `checked_transfer_from`), making this a clear inconsistency. For a non-standard BTC token that returns `false` on a failed approval instead of reverting, the pool proceeds to call `add_stake_from_pool` on the staking contract with no valid allowance set, causing the downstream `transfer_from` to fail and the entire delegation entry to revert — permanently blocking delegators from entering a BTC pool backed by such a token.

### Finding Description
`transfer_to_staking_contract` is called from both `enter_delegation_pool` and `add_to_delegation_pool`. Its body is:

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

The `approve` call returns a `bool` that is never bound or asserted. In contrast, every other token movement in the same file uses the checked wrappers:

- `exit_delegation_pool_action` → `token_dispatcher.checked_transfer(...)` [2](#0-1) 
- `claim_rewards` → `reward_token.checked_transfer(...)` [3](#0-2) 
- `transfer_from_delegator` in `pool/utils.cairo` → `token_dispatcher.checked_transfer_from(...)` [4](#0-3) 

`CheckedIERC20DispatcherTrait` is imported at the top of `pool.cairo` but is never applied to the `approve` call. [5](#0-4) 

The pool supports both STRK and BTC tokens. BTC tokens are external contracts added by governance; their `approve` implementation is not guaranteed to revert on failure. [6](#0-5) 

### Impact Explanation
If a BTC token's `approve` returns `false` without reverting, the pool sets no allowance on the staking contract and then calls `add_stake_from_pool`. The staking contract attempts `transfer_from(pool → staking, amount)` against a zero allowance; if the staking contract uses `checked_transfer_from` (as it does for STRK), that call panics and the entire transaction reverts. Because `transfer_from_delegator` already moved the delegator's tokens into the pool in the same transaction, the revert unwinds everything — but the delegator is permanently unable to enter or add to the BTC delegation pool. This is a **permanent DoS on delegation** for any BTC token whose `approve` does not revert on failure, matching the **Medium: griefing with damage to users** impact tier.

### Likelihood Explanation
The Starknet ecosystem is expanding to support BTC-backed tokens. The staking contract explicitly iterates over `btc_tokens` and the pool constructor accepts any `token_address`. A non-standard BTC-wrapped token (e.g., a bridged asset with a non-reverting `approve`) is a realistic deployment scenario. The entry path is fully unprivileged: any delegator calling `enter_delegation_pool` or `add_to_delegation_pool` on a BTC pool triggers the vulnerable code path.

### Recommendation
Replace the bare `approve` call with a checked variant that asserts the return value, consistent with the rest of the codebase:

```cairo
// Before (unsafe):
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// After (safe):
let approved = token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
assert!(approved, "{}", Error::APPROVE_FAILED);
```

Alternatively, extend `CheckedIERC20DispatcherTrait` with a `checked_approve` helper mirroring the existing `checked_transfer` / `checked_transfer_from` pattern.

### Proof of Concept
1. Governance adds a BTC token whose `approve` returns `false` instead of reverting.
2. A staker opens a BTC delegation pool via `set_open_for_delegation`.
3. A delegator calls `enter_delegation_pool(reward_address, amount)` on the BTC pool.
4. `transfer_from_delegator` succeeds — delegator's BTC tokens move to the pool.
5. `transfer_to_staking_contract` calls `token_dispatcher.approve(staking_contract, amount)` → returns `false`, silently ignored.
6. `add_stake_from_pool` is called; the staking contract calls `checked_transfer_from(pool, staking_contract, amount)` → allowance is 0 → panics.
7. The entire transaction reverts. The delegator's tokens are returned (revert), but every subsequent attempt produces the same result.
8. No delegator can ever successfully enter or add to this BTC pool.

### Citations

**File:** src/pool/pool.cairo (L47-47)
```text
    use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```

**File:** src/pool/pool.cairo (L329-330)
```text
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
```

**File:** src/pool/pool.cairo (L365-366)
```text
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
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

**File:** src/pool/utils.cairo (L124-139)
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
}
```
