Looking at the vulnerability class (missing zero-value input validation on address arguments), I need to find analogous patterns in the Starknet Staking codebase where user-supplied address arguments are accepted without zero-address checks.

From reading `src/pool/pool.cairo` and `src/staking/staking.cairo`, I can identify the following:

**`enter_delegation_pool`** (pool.cairo line 182): accepts `reward_address` and only checks it is not a token address (line 195), no `is_non_zero()` check.

**`change_reward_address`** (pool.cairo line 505): accepts `reward_address` and only checks it is not a token address (lines 506–510), no `is_non_zero()` check.

**`stake`** (staking.cairo line 288): accepts `reward_address` and only checks it is not a token address (lines 307–311), no `is_non_zero()` check.

**`change_reward_address`** (staking.cairo line 517): accepts `reward_address` and only checks it is not a token address (lines 520–524), no `is_non_zero()` check.

When `claim_rewards` is called in pool.cairo (line 366), rewards are transferred directly to the stored `reward_address` with no zero-address guard. If `reward_address = 0`, STRK rewards are permanently burned.

---

### Title
Missing Zero-Address Validation on `reward_address` Causes Permanent Burning of Delegator Yield - (File: src/pool/pool.cairo)

### Summary
`enter_delegation_pool` and `change_reward_address` in `pool.cairo` (and their counterparts in `staking.cairo`) accept a `reward_address` parameter without validating it is non-zero. A pool member who supplies or updates to `reward_address = 0` will have all subsequent reward claims permanently transferred to the zero address, irreversibly destroying their unclaimed yield.

### Finding Description
In `pool.cairo`, both public entry points that set a pool member's reward address lack a zero-address check:

**`enter_delegation_pool`** — the only address validation present is a token-address check: [1](#0-0) 

No `reward_address.is_non_zero()` assertion exists before the address is stored: [2](#0-1) 

**`change_reward_address`** — same pattern; only a token-address check is performed: [3](#0-2) 

When `claim_rewards` executes, it unconditionally transfers STRK to whatever address is stored: [4](#0-3) 

If `reward_address` is `0x0`, the `checked_transfer` sends tokens to the zero address. There is no recovery path — the tokens are permanently burned.

The identical gap exists in `staking.cairo` for both `stake` and `change_reward_address`: [5](#0-4) [6](#0-5) 

A `GenericError::ZERO_ADDRESS` variant already exists in the error catalogue, confirming the intent to guard against zero addresses in other contexts, but it is not applied here: [7](#0-6) 

### Impact Explanation
Any STRK rewards accumulated by a pool member whose `reward_address` is `0x0` are permanently destroyed on every `claim_rewards` call. Once transferred to the zero address the tokens cannot be recovered. This satisfies **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
Low-to-medium. A delegator can accidentally pass a zero address via a buggy front-end, a scripting error, or a misunderstanding of the API. Because `enter_delegation_pool` is a one-time registration call per pool member (guarded by `POOL_MEMBER_EXISTS`), a single mistaken call permanently locks the reward destination to zero until `change_reward_address` is explicitly called — and any rewards claimed in the interim are already gone. The protocol offers no protective guard. [8](#0-7) 

### Recommendation
Add a non-zero assertion on `reward_address` in all four affected functions:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply this to:
- `enter_delegation_pool` — `src/pool/pool.cairo` line 191 (after the `POOL_MEMBER_EXISTS` check)
- `change_reward_address` — `src/pool/pool.cairo` line 506 (before the token check)
- `stake` — `src/staking/staking.cairo` line 307 (before the token check)
- `change_reward_address` — `src/staking/staking.cairo` line 520 (before the token check)

### Proof of Concept
1. Delegator calls `enter_delegation_pool(reward_address: 0x0, amount: 10_000_STRK)`.
2. Pool member record is created with `reward_address = 0x0`. [2](#0-1) 
3. After K epochs, staking rewards accumulate in the pool.
4. Delegator (or anyone authorised) calls `claim_rewards(pool_member)`.
5. `claim_rewards` reads `reward_address = 0x0` and executes `checked_transfer(recipient: 0x0, amount: rewards)`. [4](#0-3) 
6. All accumulated STRK rewards are sent to the zero address and permanently destroyed. The delegator receives nothing and cannot recover the burned tokens.

### Citations

**File:** src/pool/pool.cairo (L188-191)
```text
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L193-195)
```text
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L204-207)
```text
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

```

**File:** src/pool/pool.cairo (L364-367)
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

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L520-524)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/errors.cairo (L20-20)
```text
    ZERO_ADDRESS,
```
