### Title
Missing Zero-Address Validation in `change_reward_address` Allows Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both `Staking.change_reward_address` and `Pool.change_reward_address` accept an arbitrary `ContractAddress` as the new reward destination without checking whether it is the zero address. A staker or pool member can irrevocably redirect all future reward transfers to `0x0`, permanently freezing their unclaimed yield.

---

### Finding Description

**Staking contract** — `src/staking/staking.cairo`, `change_reward_address` (lines 517–540):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    let old_address = staker_info.reward_address;
    staker_info.reward_address = reward_address;   // ← no zero-address guard
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
```

The only guard is `REWARD_ADDRESS_IS_TOKEN`; there is no `is_non_zero()` assertion on `reward_address`. [1](#0-0) 

**Pool contract** — `src/pool/pool.cairo`, `change_reward_address` (lines 505–526):

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let old_address = pool_member_info.reward_address;
    pool_member_info.reward_address = reward_address;   // ← no zero-address guard
    self.write_pool_member_info(:pool_member, :pool_member_info);
    ...
}
``` [2](#0-1) 

Once `reward_address` is stored as zero, every subsequent reward transfer targets `0x0`:

- **Staking contract** — `send_rewards_to_staker` (line 1625):
  `token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());` [3](#0-2) 

- **Pool contract** — `claim_rewards` (line 366):
  `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());` [4](#0-3) 

The protocol already defines a `ZERO_ADDRESS` error and uses `assert_caller_is_not_zero()` in `general_prerequisites`, demonstrating awareness of the zero-address class of bugs — but neither `change_reward_address` implementation applies it to the incoming parameter. [5](#0-4) 

---

### Impact Explanation

Setting `reward_address` to `0x0` causes every call to `claim_rewards` (staking) or `claim_rewards` (pool) to attempt a token transfer to the zero address. Depending on the STRK ERC-20 implementation:

- If the transfer **reverts** on zero recipient: the staker/pool member can never successfully claim rewards — **temporary (effectively permanent) freezing of unclaimed yield**.
- If the transfer **succeeds**: all accrued STRK rewards are burned to `0x0` — **permanent loss of unclaimed yield**.

Both outcomes fall within the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties"*.

---

### Likelihood Explanation

The entry path is fully unprivileged: any active staker calls `Staking.change_reward_address(0)`, and any pool member calls `Pool.change_reward_address(0)`. No special role, leaked key, or external dependency is required. The realistic trigger is an accidental or UI-induced zero-address submission (e.g., a front-end bug, a scripting error, or a malicious actor who has obtained the staker's signing key and wishes to grief them). The function is publicly callable with no cooldown or confirmation step.

---

### Recommendation

Add a non-zero assertion on `reward_address` in both `change_reward_address` implementations, mirroring the existing `assert_caller_is_not_zero` pattern:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply the same guard to the `reward_address` parameter of `stake` (staking.cairo) and `enter_delegation_pool` (pool.cairo) for defence-in-depth.

---

### Proof of Concept

**Staking contract path:**

```cairo
// 1. Staker stakes normally.
staking_dispatcher.stake(
    reward_address: valid_reward_address,
    operational_address: operational_address,
    amount: MIN_STAKE,
);

// 2. Staker (or anyone with the staker key) sets reward address to zero — succeeds with no error.
cheat_caller_address_once(contract_address: staking_contract, caller_address: staker_address);
staking_dispatcher.change_reward_address(reward_address: Zero::zero());

// 3. After rewards accrue, claim_rewards sends STRK to 0x0 — yield is permanently frozen/lost.
staking_dispatcher.claim_rewards(staker_address: staker_address);
```

**Pool member path:**

```cairo
// 1. Pool member enters delegation pool normally.
pool_dispatcher.enter_delegation_pool(reward_address: valid_reward_address, amount: AMOUNT);

// 2. Pool member sets reward address to zero — succeeds with no error.
cheat_caller_address_once(contract_address: pool_contract, caller_address: pool_member);
pool_dispatcher.change_reward_address(reward_address: Zero::zero());

// 3. claim_rewards sends STRK to 0x0 — yield is permanently frozen/lost.
pool_dispatcher.claim_rewards(pool_member: pool_member);
```

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

**File:** src/pool/pool.cairo (L505-526)
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

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardAddressChanged {
                        pool_member, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
