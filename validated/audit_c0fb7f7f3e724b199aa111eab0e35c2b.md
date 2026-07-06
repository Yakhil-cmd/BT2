### Title
Zero Address Allowed as Reward Address Causes Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Neither `staking.cairo` nor `pool.cairo` validate that a `reward_address` is non-zero when it is registered or updated. A staker or pool member can set their `reward_address` to `ContractAddress::zero()`, causing all future reward transfers to be sent to the zero address and permanently burned.

---

### Finding Description

Four entry points accept a `reward_address` without a zero-address guard:

**1. `Staking::stake()` — `src/staking/staking.cairo` lines 288–317**

The only address-related checks are that `reward_address` is not a registered token address. No `is_non_zero()` assertion exists. [1](#0-0) 

**2. `Staking::change_reward_address()` — `src/staking/staking.cairo` lines 517–540**

Same single check: not a token address. No zero-address guard. [2](#0-1) 

**3. `Pool::enter_delegation_pool()` — `src/pool/pool.cairo` lines 182–219**

Only checks `token_address != reward_address`. No zero-address guard. [3](#0-2) 

**4. `Pool::change_reward_address()` — `src/pool/pool.cairo` lines 505–526**

Only checks `token_dispatcher.contract_address.read() != reward_address`. No zero-address guard. [4](#0-3) 

When rewards are later claimed, both contracts transfer directly to the stored `reward_address`:

- **Staking** `claim_rewards` sends STRK to `staker_info.reward_address` [5](#0-4) 

- **Pool** `claim_rewards` calls `checked_transfer(recipient: reward_address, …)` at line 366 [6](#0-5) 

On StarkNet, a transfer to `ContractAddress::zero()` does not revert — the tokens are permanently burned.

---

### Impact Explanation

Any staker or pool member who sets `reward_address` to zero (accidentally or through a front-end bug) will have every future reward payment sent to address(0). The tokens are irrecoverable. This constitutes **permanent freezing of unclaimed yield** (High severity per the allowed impact scope).

---

### Likelihood Explanation

The call path is fully permissionless: any staker calls `change_reward_address(0)` on the staking contract, or any pool member calls `change_reward_address(0)` on the pool contract. No privileged role is required. The risk is realistic given that zero is a natural default/sentinel value that a buggy front-end or script might pass.

---

### Recommendation

Add a non-zero assertion at the top of every function that accepts or stores a `reward_address`:

```cairo
assert!(reward_address.is_non_zero(), "reward address is zero");
```

This should be applied in:
- `Staking::stake()` — `src/staking/staking.cairo`
- `Staking::change_reward_address()` — `src/staking/staking.cairo`
- `Pool::enter_delegation_pool()` — `src/pool/pool.cairo`
- `Pool::change_reward_address()` — `src/pool/pool.cairo`

---

### Proof of Concept

**Pool member path (minimal):**

1. A pool member calls `Pool::enter_delegation_pool(reward_address: 0, amount: X)` — accepted without revert. [7](#0-6) 

2. Epochs pass; the staking contract distributes rewards to the pool via `update_rewards_from_staking_contract`.

3. The pool member (or anyone) calls `Pool::claim_rewards(pool_member)`.

4. Inside `claim_rewards`, `reward_token.checked_transfer(recipient: reward_address /* == 0 */, amount: rewards)` executes successfully, sending all accrued STRK to address(0). [6](#0-5) 

5. Rewards are permanently lost; the pool member's `reward_address` remains zero for all future claims.

**Staker path:** identical flow via `Staking::change_reward_address(0)` followed by `Staking::claim_rewards(staker_address)`. [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L415-420)
```text
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
```

**File:** src/staking/staking.cairo (L517-531)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let old_address = staker_info.reward_address;

            // Update reward_address and commit to storage.
            staker_info.reward_address = reward_address;
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/pool/pool.cairo (L182-206)
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
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
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
