### Title
Missing Zero-Address Validation on `reward_address` Allows Permanent Freezing of Staker Funds and Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `staking.cairo::stake()` and `staking.cairo::change_reward_address()` (and the pool analog `pool.cairo::change_reward_address()`) accept a `reward_address` parameter without checking it against the zero address. When rewards are later claimed or a staker attempts to exit, the protocol unconditionally transfers STRK to the stored `reward_address`. If that address is zero, the ERC20 transfer reverts (OpenZeppelin Cairo ERC20 rejects zero-address recipients), permanently bricking `unstake_action` and freezing both unclaimed yield and the staker's principal.

---

### Finding Description

**Root cause — `staking.cairo::stake()`** (lines 288–366):

The `reward_address` parameter is validated only against the token registry (`does_token_exist`), with no zero-address guard:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
```

No `assert!(reward_address.is_non_zero(), ...)` is present. [1](#0-0) 

**Root cause — `staking.cairo::change_reward_address()`** (lines 517–540):

The same single check is applied; zero address is not rejected:

```cairo
assert!(
    !self.does_token_exist(token_address: reward_address),
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [2](#0-1) 

**Root cause — `pool.cairo::change_reward_address()`** (lines 505–526):

Only the pool's own token address is excluded; zero is not:

```cairo
assert!(
    self.token_dispatcher.contract_address.read() != reward_address,
    "{}",
    GenericError::REWARD_ADDRESS_IS_TOKEN,
);
``` [3](#0-2) 

**Trigger path — `send_rewards_to_staker()`** (lines 1614–1629):

Every reward-bearing exit path calls this function, which unconditionally transfers to the stored `reward_address`:

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [4](#0-3) 

**Trigger path — `unstake_action()`** (lines 483–515):

`unstake_action` calls `send_rewards_to_staker` before returning the principal. If the reward transfer reverts, the entire unstake reverts, permanently locking the staker's principal: [5](#0-4) 

**Trigger path — `pool.cairo::claim_rewards()`** (lines 335–377):

Pool member rewards are transferred directly to `reward_address` with no zero guard:

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [6](#0-5) 

The `GenericError::ZERO_ADDRESS` variant exists in the shared error module and is already used elsewhere (e.g., `assert_caller_is_not_zero`), confirming the pattern is known but was not applied to `reward_address` setters. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**For stakers**: Setting `reward_address` to zero (at `stake()` time or via `change_reward_address()`) causes `unstake_action` to always revert once any rewards have accrued, because `send_rewards_to_staker` attempts `checked_transfer(recipient: 0x0, ...)` which the STRK ERC20 rejects. The staker's principal is permanently locked in the contract with no recovery path.

**For pool members**: `claim_rewards` reverts on every call, permanently freezing all accrued yield. The pool member's delegated stake is also unrecoverable if the pool's staker unstakes (the pool receives its principal back, but the member can never withdraw rewards).

Both outcomes fall within the allowed impact scope: **permanent freezing of unclaimed yield** and **temporary/permanent freezing of funds**.

---

### Likelihood Explanation

The entry point (`stake`, `change_reward_address`) is callable by any unprivileged staker or pool member with no preconditions beyond having an active position. Accidental misconfiguration (e.g., passing an uninitialized address variable) is a realistic scenario. No privileged role, leaked key, or external dependency is required.

---

### Recommendation

Add a zero-address assertion in all three entry points:

**`staking.cairo::stake()` and `staking.cairo::change_reward_address()`**:
```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

**`pool.cairo::change_reward_address()`**:
```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

The `GenericError::ZERO_ADDRESS` variant and its description `"Address is zero"` are already defined and ready to use. [9](#0-8) 

---

### Proof of Concept

1. Staker calls `stake(reward_address: 0x0, operational_address: <valid>, amount: <min_stake>)`.
   - The only check on `reward_address` is `does_token_exist(0x0)` → returns `false` → passes.
   - Staker is registered with `reward_address = 0x0`.
2. One or more epochs pass; `update_global_index` is called; `unclaimed_rewards_own` becomes non-zero.
3. Staker calls `unstake_intent()` → succeeds (no reward transfer here).
4. After the exit window, staker calls `unstake_action(staker_address)`:
   - `send_rewards_to_staker` is invoked.
   - `claim_from_reward_supplier` transfers STRK to the staking contract.
   - `checked_transfer(recipient: 0x0, amount: rewards)` is called on the STRK ERC20.
   - The ERC20 reverts with a zero-address transfer error.
   - The entire `unstake_action` reverts.
5. The staker's principal is permanently locked; no recovery function exists.

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

**File:** src/staking/staking.cairo (L519-524)
```text
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

**File:** src/errors.cairo (L19-20)
```text
    ZERO_CLASS_HASH,
    ZERO_ADDRESS,
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
