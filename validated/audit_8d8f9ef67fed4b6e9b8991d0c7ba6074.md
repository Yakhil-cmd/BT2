### Title
Unchecked `approve()` Return Value in Pool's `transfer_to_staking_contract` Breaks BTC Token Delegation - (File: src/pool/pool.cairo)

### Summary
The `Pool` contract calls `token_dispatcher.approve()` directly without checking its return value in `transfer_to_staking_contract`. Every other token operation in the codebase uses `CheckedIERC20DispatcherTrait` (`checked_transfer`, `checked_transfer_from`), but the approval step is inconsistently left unchecked. For a BTC token whose `approve()` returns `false` instead of reverting, the pool silently proceeds to `add_stake_from_pool`, which then calls `checked_transfer_from` and reverts due to zero allowance — permanently breaking delegation entry for that token.

### Finding Description
In `src/pool/pool.cairo`, the internal function `transfer_to_staking_contract` is responsible for approving the staking contract to pull delegated funds from the pool, then notifying the staking contract:

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

The `approve()` call uses the raw `IERC20Dispatcher`, not `CheckedIERC20DispatcherTrait`. Its `bool` return value is silently discarded. By contrast, every other token interaction in the pool uses the checked variant:

- `transfer_from_delegator` uses `checked_transfer_from` [2](#0-1) 
- `exit_delegation_pool_action` uses `checked_transfer` [3](#0-2) 
- `claim_rewards` uses `checked_transfer` [4](#0-3) 

`CheckedIERC20DispatcherTrait` is imported in both `pool.cairo` and `pool/utils.cairo` but never applied to the `approve` step. [5](#0-4) 

The staking contract's `add_stake_from_pool` then calls `checked_transfer_from` on the pool contract: [6](#0-5) 

If `approve()` returned `false` (silently ignored), this `checked_transfer_from` will revert because the allowance is still zero.

`transfer_to_staking_contract` is called from two public entry points reachable by any unprivileged delegator:
- `enter_delegation_pool` [7](#0-6) 
- `add_to_delegation_pool` [8](#0-7) 

The protocol explicitly supports arbitrary BTC tokens added by governance. The pool constructor accepts any `token_address` and stores it as `token_dispatcher`: [9](#0-8) 

### Impact Explanation
For any BTC token whose `approve()` returns `false` rather than reverting (a valid ERC-20 pattern), every call to `enter_delegation_pool` and `add_to_delegation_pool` will revert at the `checked_transfer_from` step inside `add_stake_from_pool`. The entire delegation flow for that token is permanently broken. Delegators cannot enter or increase their position in any pool backed by such a token. This constitutes permanent griefing of users and the protocol with no profit motive — matching the **Medium: Griefing with no profit motive but damage to users or protocol** impact class.

### Likelihood Explanation
The protocol is designed to support multiple BTC tokens added via governance. Non-standard ERC-20 `approve()` implementations that return `false` on failure (rather than reverting) are a known pattern. The inconsistency is structural: the codebase already imports and uses `CheckedIERC20DispatcherTrait` everywhere else, making this omission an oversight rather than an intentional design choice. Any BTC token with this behavior triggers the bug on every delegation attempt.

### Recommendation
Replace the direct `approve()` call with a checked variant, consistent with all other token operations in the codebase:

```cairo
// Replace:
token_dispatcher
    .approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());

// With:
token_dispatcher
    .checked_approve(spender: staking_pool_dispatcher.contract_address, amount: amount.into());
```

If `CheckedIERC20DispatcherTrait` does not yet expose `checked_approve`, extend it analogously to `checked_transfer` and `checked_transfer_from`.

### Proof of Concept
1. Governance adds a BTC token whose `approve()` returns `false` on any call (or under specific conditions such as a blacklist).
2. A staker calls `set_open_for_delegation(token_address)` — a pool contract is deployed for that token.
3. A delegator approves the pool contract to spend their BTC tokens.
4. The delegator calls `enter_delegation_pool(reward_address, amount)`.
5. `transfer_from_delegator` succeeds — funds move from delegator to pool.
6. `transfer_to_staking_contract` calls `token_dispatcher.approve(...)` — returns `false`, silently ignored.
7. `add_stake_from_pool` calls `checked_transfer_from(sender: pool_contract, ...)` — reverts because allowance is 0.
8. The entire transaction reverts. Step 5 is rolled back, so delegator funds are returned.
9. Steps 4–8 repeat on every attempt: delegation is permanently broken for this token across all pools.

### Citations

**File:** src/pool/pool.cairo (L47-47)
```text
    use starkware_utils::erc20::erc20_utils::CheckedIERC20DispatcherTrait;
```

**File:** src/pool/pool.cairo (L154-161)
```text
        token_address: ContractAddress,
        governance_admin: ContractAddress,
    ) {
        self.roles.initialize(:governance_admin);
        self.replaceability.initialize(upgrade_delay: Zero::zero());
        self.staker_address.write(staker_address);
        self.staking_pool_dispatcher.contract_address.write(staking_contract);
        self.token_dispatcher.contract_address.write(token_address);
```

**File:** src/pool/pool.cairo (L196-199)
```text
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L237-239)
```text
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
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

**File:** src/pool/utils.cairo (L24-27)
```text
    token_dispatcher
        .checked_transfer_from(
            sender: pool_member, recipient: self_contract, amount: amount.into(),
        );
```

**File:** src/staking/staking.cairo (L1030-1034)
```text
            let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
            token_dispatcher
                .checked_transfer_from(
                    sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
                );
```
