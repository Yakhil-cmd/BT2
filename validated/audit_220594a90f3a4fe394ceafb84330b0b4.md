### Title
Incomplete Reward Address Validation in BTC Pool Allows Permanent Freezing of STRK Rewards - (File: src/pool/pool.cairo)

### Summary

The `change_reward_address` and `enter_delegation_pool` functions in `pool.cairo` only validate that `reward_address` is not equal to the pool's own staking token. For BTC delegation pools, this means the STRK token address (the actual reward token) is never blocked. A pool member can set their `reward_address` to `STRK_TOKEN_ADDRESS`, causing all future STRK reward claims to be transferred into the STRK token contract itself, permanently locking them with no recovery path.

### Finding Description

Pool rewards are always distributed in STRK, regardless of the pool's staking token: [1](#0-0) 

The `change_reward_address` function validates only against the pool's own staking token: [2](#0-1) 

For a BTC pool, `self.token_dispatcher.contract_address` is the BTC token address — not `STRK_TOKEN_ADDRESS`. The check therefore never blocks a pool member from setting `reward_address = STRK_TOKEN_ADDRESS`.

The same incomplete check exists at pool entry: [3](#0-2) 

By contrast, the staking contract's `change_reward_address` correctly uses `does_token_exist`, which covers all registered tokens including STRK: [4](#0-3) 

The pool contract lacks this broader check.

### Impact Explanation

Once `reward_address` is set to `STRK_TOKEN_ADDRESS`, every subsequent `claim_rewards` call executes:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
// reward_address == STRK_TOKEN_ADDRESS → STRK sent into the STRK contract itself
```

The STRK token contract has no sweep or recovery function. All rewards transferred there are permanently frozen. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- BTC pools are a live, supported feature of the protocol.
- A pool member who confuses the STRK token address with a valid reward address (e.g., copy-paste error, wallet UI mistake, or scripting error) will silently lose all future rewards with no on-chain warning.
- The entry point (`enter_delegation_pool` or `change_reward_address`) is callable by any unprivileged pool member — no privileged role required.
- The error is silent: `claim_rewards` succeeds and emits a `PoolMemberRewardClaimed` event showing a non-zero amount, but the funds go to the token contract.

### Recommendation

In `pool.cairo`, extend both `enter_delegation_pool` and `change_reward_address` to also reject `STRK_TOKEN_ADDRESS` as a reward address, mirroring the staking contract's `does_token_exist` pattern:

```cairo
assert!(
    reward_address != STRK_TOKEN_ADDRESS,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

Or, more robustly, maintain a set of all known token addresses in the pool contract (or query the staking contract) and reject any of them as a reward address.

### Proof of Concept

1. Staker opens a BTC delegation pool via `set_open_for_delegation(btc_token_address)`.
2. Pool member calls `enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount: X)` on the BTC pool. The only check is `btc_token_address != STRK_TOKEN_ADDRESS` — passes.
3. Epochs advance; the staking contract distributes STRK rewards to the pool contract via `update_rewards_from_staking_contract`.
4. Pool member (or anyone) calls `claim_rewards(pool_member)`. The function computes non-zero `rewards` and executes `strk_token.transfer(recipient: STRK_TOKEN_ADDRESS, amount: rewards)`.
5. The STRK token contract receives the tokens into its own balance. No recovery function exists. Rewards are permanently frozen. [5](#0-4) [6](#0-5) [1](#0-0)

### Citations

**File:** src/pool/pool.cairo (L182-195)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L505-517)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_address = pool_member_info.reward_address;

            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);
```

**File:** src/staking/staking.cairo (L519-524)
```text
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
