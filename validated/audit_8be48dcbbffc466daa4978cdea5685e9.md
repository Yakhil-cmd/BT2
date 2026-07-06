### Title
Wrong Token Checked in Pool Reward Address Validation Allows Permanent Loss of Unclaimed STRK Yield - (File: src/pool/pool.cairo)

### Summary
In `pool.cairo`, both `change_reward_address` and `enter_delegation_pool` validate the reward address only against the pool's own staking token (`self.token_dispatcher.contract_address`). For a BTC delegation pool, this means the STRK token address is never checked. Since all pool rewards are always paid in STRK, a BTC pool member can set their reward address to `STRK_TOKEN_ADDRESS`, causing `claim_rewards` to transfer STRK rewards into the STRK token contract itself — permanently freezing unclaimed yield.

### Finding Description

The pool contract stores its staking token in `self.token_dispatcher`: [1](#0-0) 

In `change_reward_address`, the guard only checks the pool's own staking token: [2](#0-1) 

For a BTC pool, `self.token_dispatcher.contract_address` is the BTC token address. The assertion `BTC_TOKEN_ADDRESS != STRK_TOKEN_ADDRESS` trivially passes, so setting `reward_address = STRK_TOKEN_ADDRESS` is allowed.

The same incomplete check exists in `enter_delegation_pool`: [3](#0-2) 

However, `claim_rewards` always pays out in STRK regardless of the pool's staking token: [4](#0-3) 

So when `claim_rewards` is called for a BTC pool member whose `reward_address` is `STRK_TOKEN_ADDRESS`, STRK rewards are transferred into the STRK token contract itself, where they are unrecoverable.

By contrast, the staking contract's own `change_reward_address` correctly checks against **all** registered tokens via `does_token_exist`: [5](#0-4) 

The pool contract never calls an equivalent multi-token check — it only checks its single staking token, which is the wrong token to check when the reward token is always STRK.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

A BTC pool member who sets `reward_address = STRK_TOKEN_ADDRESS` (either by mistake or through a griefing scenario) will have all future STRK reward claims sent to the STRK token contract. The STRK ERC20 contract has no recovery mechanism for tokens sent to it, so the rewards are permanently frozen. The `claim_rewards` function marks `_unclaimed_rewards_from_v0` as zero and advances `reward_checkpoint` after the transfer, so the loss is irreversible even if the reward address is later corrected. [6](#0-5) 

### Likelihood Explanation

**Medium.** BTC delegation pools are a core, deployed feature of the protocol. Any BTC pool member can call `change_reward_address` permissionlessly. The missing guard is subtle — a user migrating from a STRK pool to a BTC pool might reasonably attempt to set their reward address to a STRK-related address. The check appears to exist (the error `REWARD_ADDRESS_IS_TOKEN` is emitted) but silently fails to cover the reward token for BTC pools.

### Recommendation

In `pool.cairo`, replace the single-token check in both `change_reward_address` and `enter_delegation_pool` with a check against all protocol tokens. The simplest fix is to also assert the reward address is not `STRK_TOKEN_ADDRESS`:

```cairo
// change_reward_address
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
assert!(
    STRK_TOKEN_ADDRESS != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

Or, preferably, expose a `does_token_exist` query on the staking contract and call it from the pool, mirroring the pattern already used in `staking.cairo`: [5](#0-4) 

### Proof of Concept

1. A BTC delegation pool is deployed via `set_open_for_delegation(btc_token_address)`.
2. A delegator calls `enter_delegation_pool(reward_address: STRK_TOKEN_ADDRESS, amount: X)` on the BTC pool. The check at line 195 evaluates `BTC_TOKEN_ADDRESS != STRK_TOKEN_ADDRESS` → `true`, so the call succeeds.
3. Alternatively, an existing BTC pool member calls `change_reward_address(STRK_TOKEN_ADDRESS)`. The check at line 507 evaluates `BTC_TOKEN_ADDRESS != STRK_TOKEN_ADDRESS` → `true`, so the call succeeds.
4. After rewards accrue, anyone calls `claim_rewards(pool_member)`.
5. Line 365–366 executes: `IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS }.checked_transfer(recipient: STRK_TOKEN_ADDRESS, amount: rewards)`.
6. STRK rewards are transferred into the STRK token contract itself and are permanently unrecoverable. [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L106-106)
```text
        token_dispatcher: IERC20Dispatcher,
```

**File:** src/pool/pool.cairo (L192-195)
```text
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L356-366)
```text
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L505-510)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
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
