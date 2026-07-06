### Title
Missing Zero-Address Validation for `reward_address` Causes Temporary Freezing of Staker Principal - (File: src/staking/staking.cairo)

---

### Summary

The `stake()` and `change_reward_address()` functions in `staking.cairo`, and `enter_delegation_pool()` and `change_reward_address()` in `pool.cairo`, accept a `reward_address` parameter with no zero-address check. If a staker or pool member sets `reward_address` to `0`, the `unstake_action()` flow unconditionally attempts an ERC20 transfer to address zero, which reverts on the STRK token, permanently blocking principal withdrawal until the reward address is corrected.

---

### Finding Description

In `staking.cairo`, the `stake()` function validates `reward_address` only against the token registry:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

There is no `reward_address.is_non_zero()` guard. The same omission exists in `change_reward_address()` in `staking.cairo`, and in both `enter_delegation_pool()` and `change_reward_address()` in `pool.cairo`.

When `unstake_action()` is called, it unconditionally invokes `send_rewards_to_staker()`:

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;
    let amount = staker_info.unclaimed_rewards_own;
    claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
    ...
}
```

There is no guard on `amount.is_zero()` before the transfer, and no guard on `reward_address.is_non_zero()`. The STRK ERC20 (OpenZeppelin-based) reverts on any transfer to address zero, including zero-amount transfers. Because `send_rewards_to_staker()` is called before the principal is returned to the staker, a revert here blocks the entire `unstake_action()` execution, leaving the staker's principal locked in the staking contract.

The same pattern applies in `pool.cairo`'s `claim_rewards()`, which transfers to `reward_address` without a zero check.

---

### Impact Explanation

A staker who sets `reward_address` to `0` (either by mistake or by passing zero at `stake()` time) will find that `unstake_action()` always reverts. The staker's principal — which may be the protocol minimum stake or far more — is held in the staking contract and cannot be recovered until `change_reward_address()` is called with a valid address. This constitutes a **temporary freezing of funds** (principal) and a **temporary freezing of unclaimed yield** (rewards cannot be claimed while `reward_address` is zero).

If the STRK ERC20 implementation were to silently accept transfers to address zero (burning them), the impact escalates to **permanent loss of unclaimed yield**.

---

### Likelihood Explanation

Any unprivileged staker or pool member can trigger this by passing `reward_address = 0` to `stake()` or `enter_delegation_pool()`, or by calling `change_reward_address(0)` at any point. No privileged access is required. The protocol provides no guard against this input. While a rational actor would not intentionally lock their own funds, accidental zero-address submission is a realistic user error, and the protocol's job is to reject it at the boundary.

---

### Recommendation

Add a non-zero assertion for `reward_address` in all four entry points:

1. `stake()` in `staking.cairo`
2. `change_reward_address()` in `staking.cairo`
3. `enter_delegation_pool()` in `pool.cairo`
4. `change_reward_address()` in `pool.cairo`

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The `assert_caller_is_not_zero()` utility already exists in `src/staking/utils.cairo` and demonstrates the pattern; a parallel `assert_reward_address_is_not_zero()` or an inline assertion should be applied consistently.

---

### Proof of Concept

1. Deploy the staking system.
2. Call `stake(reward_address: 0, operational_address: <valid>, amount: min_stake)`. The call succeeds because the only check is `!does_token_exist(0)`, which passes (zero is not a registered token).
3. Advance time past the exit wait window.
4. Call `unstake_intent()`. Succeeds.
5. Advance time past the exit wait window.
6. Call `unstake_action(staker_address)`. This calls `send_rewards_to_staker()`, which calls `checked_transfer(recipient: 0, amount: ...)`. The STRK ERC20 reverts on transfer to address zero. `unstake_action()` reverts. The staker's principal remains locked in the staking contract.
7. The staker must call `change_reward_address(<valid_address>)` and then retry `unstake_action()` to recover their funds.

**Relevant code locations:**

- Missing zero check in `stake()`: [1](#0-0) 
- Missing zero check in `change_reward_address()` (staking): [2](#0-1) 
- Missing zero check in `enter_delegation_pool()` (pool): [3](#0-2) 
- Missing zero check in `change_reward_address()` (pool): [4](#0-3) 
- Unconditional transfer to `reward_address` in `send_rewards_to_staker()`: [5](#0-4) 
- `unstake_action()` calls `send_rewards_to_staker()` before returning principal: [6](#0-5) 
- `assert_caller_is_not_zero` utility showing the existing zero-check pattern: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L494-506)
```text
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
```

**File:** src/staking/staking.cairo (L520-524)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L1620-1625)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

**File:** src/pool/pool.cairo (L194-195)
```text
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
```

**File:** src/pool/pool.cairo (L506-510)
```text
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
