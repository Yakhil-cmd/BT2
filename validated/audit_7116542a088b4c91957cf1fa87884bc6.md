### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Both `staking.cairo::change_reward_address` and `pool.cairo::change_reward_address` accept a zero address as a valid `reward_address`. Any staker or pool member can set their reward destination to `0x0`. All subsequently claimed STRK rewards are then transferred to the zero address and permanently burned.

---

### Finding Description

`staking.cairo::change_reward_address` validates only that the new address is not a registered token address, but performs no zero-address check:

```cairo
// src/staking/staking.cairo lines 517-540
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← NO zero-address check
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    staker_info.reward_address = reward_address;   // zero is written here
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
```

The same omission exists in `pool.cairo::change_reward_address`:

```cairo
// src/pool/pool.cairo lines 505-526
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← NO zero-address check
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    pool_member_info.reward_address = reward_address;   // zero is written here
    ...
}
```

Once `reward_address` is set to zero, every downstream reward transfer goes to the zero address:

- `staking.cairo::send_rewards_to_staker` (line 1625): `token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into())` — called by both `claim_rewards` and `unstake_action`.
- `pool.cairo::claim_rewards` (line 366): `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())`.

The `stake` function at initial entry also lacks this check (lines 308–311), but the post-entry `change_reward_address` path is the most dangerous because rewards have already accrued.

The codebase already defines `GenericError::ZERO_ADDRESS` and uses it in other contexts, confirming the pattern is known but was not applied here.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

When a staker or pool member sets `reward_address` to zero and then calls `claim_rewards` (or triggers `unstake_action`), all accumulated STRK rewards are transferred to address `0x0`. On Starknet, ERC20 `transfer` to the zero address does not revert by default; the tokens are permanently unrecoverable. The staker's principal is unaffected, but every wei of earned yield is destroyed.

---

### Likelihood Explanation

**Medium.** The call is restricted to the staker/pool member themselves (access control: "Only staker address" / "Only pool member address"), so an external attacker cannot directly trigger it. However:

1. A user can accidentally pass `0` as the new reward address — a common fat-finger mistake with no on-chain safety net.
2. A compromised or malicious front-end could silently submit `reward_address = 0`.
3. There is no confirmation step or time-lock; the change is immediate and irreversible.

The combination of a one-step irreversible operation and no zero guard makes accidental permanent loss realistic.

---

### Recommendation

Add an explicit zero-address assertion in both `change_reward_address` implementations, mirroring the existing `ZERO_ADDRESS` error already defined in the codebase:

```cairo
// staking.cairo::change_reward_address
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);

// pool.cairo::change_reward_address
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply the same guard to the `reward_address` parameter in `stake` and `enter_delegation_pool` for defense-in-depth.

---

### Proof of Concept

1. Staker calls `staking.stake(reward_address: VALID, ...)` — staker is registered.
2. Staker earns rewards over several epochs via attestation.
3. Staker calls `staking.change_reward_address(reward_address: 0x0)` — succeeds; no revert.
4. Staker calls `staking.claim_rewards(staker_address)`.
5. `send_rewards_to_staker` executes `checked_transfer(recipient: 0x0, amount: rewards)` — tokens are sent to the zero address and permanently lost.
6. `staker_info.unclaimed_rewards_own` is zeroed out; the rewards are unrecoverable.

The same sequence applies to a pool member via `pool.change_reward_address(0x0)` followed by `pool.claim_rewards(pool_member)`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
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

**File:** src/errors.cairo (L38-39)
```text
            GenericError::ZERO_CLASS_HASH => "Class hash is zero",
            GenericError::ZERO_ADDRESS => "Address is zero",
```
