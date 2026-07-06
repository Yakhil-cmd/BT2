### Title
Missing Self-Address Validation on `reward_address` Parameter Causes Permanent Freezing of Unclaimed STRK Rewards - (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both the `Staking` and `Pool` contracts accept a `reward_address` parameter in their entry/change functions but only validate that the address is not a registered token. Neither contract checks whether `reward_address` equals the contract's own address. When rewards are claimed, STRK is transferred to `reward_address` via a plain ERC-20 `transfer`. If `reward_address` is the staking or pool contract itself, the transfer succeeds (self-transfer is valid ERC-20), the internal `unclaimed_rewards_own` counter is zeroed, and the STRK is permanently unrecoverable — neither contract exposes a sweep or recovery function.

---

### Finding Description

**Staking contract — two entry points:**

`stake()` in `src/staking/staking.cairo` accepts `reward_address: ContractAddress` and validates only:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [1](#0-0) 

There is no check that `reward_address != get_contract_address()`. The same single-check pattern appears in `change_reward_address()`: [2](#0-1) 

When rewards are later claimed, `send_rewards_to_staker` first pulls STRK from the reward supplier into the staking contract, then immediately transfers it to `reward_address`:

```cairo
claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
staker_info.unclaimed_rewards_own = Zero::zero();
``` [3](#0-2) 

If `reward_address == staking_contract_address`, the ERC-20 transfer is a no-op on the balance (self-transfer), `unclaimed_rewards_own` is zeroed, and the STRK is permanently stuck in the staking contract with no recovery path.

**Pool contract — two entry points:**

`enter_delegation_pool()` in `src/pool/pool.cairo` validates only:

```cairo
assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
``` [4](#0-3) 

`change_reward_address()` validates only:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [5](#0-4) 

Neither checks `reward_address != get_contract_address()`. When `claim_rewards` is called in the pool:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [6](#0-5) 

If `reward_address == pool_contract_address`, STRK rewards are transferred to the pool contract itself and are permanently frozen there.

---

### Impact Explanation

**Permanent freezing of unclaimed STRK yield.** The staking contract and pool contract have no sweep, rescue, or recovery function. Once rewards are transferred to the contract itself and the internal counter is zeroed, those STRK tokens are irrecoverable. This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

Any unprivileged staker or pool member can trigger this at will. The `reward_address` parameter is fully attacker-controlled and is accepted without restriction beyond the token-address check. The attacker does not need any privileged role, leaked key, or external dependency — they simply pass the staking or pool contract address as `reward_address` during `stake()`, `enter_delegation_pool()`, or the respective `change_reward_address()` call. The action is irreversible once committed.

---

### Recommendation

Add a self-address guard in all four entry points:

**`staking.cairo` — `stake()` and `change_reward_address()`:**
```cairo
assert!(
    reward_address != get_contract_address(),
    "{}",
    Error::REWARD_ADDRESS_IS_STAKING_CONTRACT,
);
```

**`pool.cairo` — `enter_delegation_pool()` and `change_reward_address()`:**
```cairo
assert!(
    reward_address != get_contract_address(),
    "{}",
    Error::REWARD_ADDRESS_IS_POOL_CONTRACT,
);
```

---

### Proof of Concept

**Staking contract scenario:**

1. Attacker (Alice) calls `staking.stake(reward_address: staking_contract_address, operational_address: ..., amount: min_stake)`.
2. The only `reward_address` check (`!does_token_exist`) passes because the staking contract is not a registered token.
3. Alice's staker record is created with `reward_address = staking_contract_address`.
4. After rewards accrue, Alice (or anyone) calls `staking.claim_rewards(staker_address: alice)`.
5. `send_rewards_to_staker` pulls STRK from the reward supplier into the staking contract, then calls `strk_token.transfer(recipient: staking_contract_address, amount: rewards)` — a self-transfer that succeeds.
6. `unclaimed_rewards_own` is set to zero. The STRK is now in the staking contract with no accounting entry and no recovery function. Rewards are permanently frozen.

**Pool contract scenario (analogous):**

1. Attacker calls `pool.enter_delegation_pool(reward_address: pool_contract_address, amount: ...)`.
2. The only check (`token_address != reward_address`) passes.
3. After rewards are forwarded from the staking contract to the pool, attacker calls `pool.claim_rewards(pool_member: attacker)`.
4. `reward_token.transfer(recipient: pool_contract_address, amount: rewards)` — self-transfer succeeds, rewards counter zeroed, STRK permanently frozen in the pool contract. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L288-317)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L517-524)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

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

**File:** src/pool/pool.cairo (L365-366)
```text
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L506-510)
```text
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
