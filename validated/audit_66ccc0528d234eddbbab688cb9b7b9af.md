### Title
Unchecked `approve` Return Value in Pool Contract Breaks Delegation for Non-Standard Tokens - (File: src/pool/pool.cairo)

### Summary
The `transfer_to_staking_contract` internal function in the Pool contract calls `token_dispatcher.approve(...)` using the raw `IERC20Dispatcher` without checking the return value. If a supported token's `approve` returns `false` rather than reverting, the pool contract silently proceeds, causing the subsequent `checked_transfer_from` in the staking contract to revert due to insufficient allowance. This permanently breaks the delegation entry path for any such token.

### Finding Description
In `src/pool/pool.cairo`, the internal helper `transfer_to_staking_contract` (lines 668–682) is called by both `enter_delegation_pool` and `add_to_delegation_pool` whenever a delegator deposits funds. The function approves the staking contract to pull tokens from the pool, then calls `add_stake_from_pool`:

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

The `approve` call uses the plain `IERC20Dispatcher`, not the `CheckedIERC20DispatcherTrait` that is used everywhere else in the file for transfers. [2](#0-1) 

The return value of `approve` is silently discarded. In Cairo, ignoring a return value does not cause a revert. If the token's `approve` returns `false`, execution continues into `add_stake_from_pool`, which internally calls `checked_transfer_from` on the staking contract side:

```cairo
token_dispatcher
    .checked_transfer_from(
        sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
    );
``` [3](#0-2) 

Because the allowance was never actually set, `checked_transfer_from` reverts. The entire delegation transaction fails. Since the pool contract supports not only STRK but also BTC-denominated tokens (the `token_dispatcher` is set per-pool at construction time from the `token_address` argument), any BTC-wrapped token whose `approve` does not revert on failure but returns `false` will make its delegation pool permanently unusable.

### Impact Explanation
Every call to `enter_delegation_pool` and `add_to_delegation_pool` for an affected token will revert at the `checked_transfer_from` step. No delegator can ever successfully stake into a BTC pool backed by such a token. This constitutes griefing with damage to users and the protocol: the pool contract is deployed and stakers can open it for delegation, but no delegator can ever enter, effectively making the pool a dead end. This matches the **Medium – griefing with no profit motive but damage to users or protocol** impact tier.

### Likelihood Explanation
The pool contract is explicitly designed to support multiple token types beyond STRK, including BTC-denominated tokens added via `set_open_for_delegation`. [4](#0-3) 

The specific BTC token address is supplied at pool deployment and is not restricted to a single known implementation. Any wrapped BTC token on Starknet whose `approve` returns `false` on failure (rather than panicking) triggers this path. While standard OpenZeppelin Cairo ERC20 tokens always return `true`, the protocol's multi-token design means the set of tokens is open-ended, making this a realistic concern as new BTC tokens are onboarded.

### Recommendation
Replace the raw `IERC20Dispatcher.approve` call with a checked variant that asserts the return value is `true`, mirroring the pattern already used for transfers throughout the codebase:

```cairo
// Instead of:
token_dispatcher.approve(spender: ..., amount: ...);

// Use a checked approve that panics on false return:
let success = token_dispatcher.approve(spender: ..., amount: ...);
assert!(success, "ERC20: approve returned false");
```

Alternatively, introduce a `checked_approve` helper in `starkware_utils::erc20::erc20_utils` consistent with the existing `CheckedIERC20DispatcherTrait` pattern.

### Proof of Concept
1. A BTC-wrapped token is registered in the staking contract via `add_token` (admin action, already done at deployment).
2. A staker calls `set_open_for_delegation(token_address: btc_token)`, deploying a BTC pool contract.
3. The BTC token's `approve` implementation returns `false` on any call (non-reverting failure path).
4. A delegator calls `pool.enter_delegation_pool(reward_address, amount)`.
5. `transfer_from_delegator` succeeds — funds move from delegator to pool contract.
6. `transfer_to_staking_contract` calls `token_dispatcher.approve(staking_contract, amount)` — returns `false`, silently ignored.
7. `staking_pool_dispatcher.add_stake_from_pool(staker_address, amount)` is called.
8. Inside `add_stake_from_pool`, `checked_transfer_from(sender: pool_contract, ...)` reverts because allowance is 0.
9. The entire transaction reverts. The delegator cannot enter the pool. The pool is permanently unusable for delegation. [5](#0-4) [6](#0-5)

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

**File:** src/staking/staking.cairo (L542-571)
```text
        fn set_open_for_delegation(
            ref self: ContractState, token_address: ContractAddress,
        ) -> ContractAddress {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(self.does_token_exist(:token_address), "{}", Error::TOKEN_NOT_EXISTS);
            assert!(
                !staker_pool_info.has_pool_for_token(:token_address),
                "{}",
                Error::STAKER_ALREADY_HAS_POOL,
            );
            let commission = staker_pool_info.commission();

            // Deploy delegation pool contract.
            let pool_contract = self
                .deploy_delegation_pool_from_staking_contract(
                    :staker_address,
                    staking_contract: get_contract_address(),
                    :token_address,
                    :commission,
                );
            // Update pool to storage.
            staker_pool_info.pools.write(pool_contract, token_address);
            // Initialize the delegated balance trace.
            self.initialize_staker_delegated_balance_trace(:staker_address, :pool_contract);
            pool_contract
```

**File:** src/staking/staking.cairo (L1030-1034)
```text
            let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
            token_dispatcher
                .checked_transfer_from(
                    sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
                );
```
