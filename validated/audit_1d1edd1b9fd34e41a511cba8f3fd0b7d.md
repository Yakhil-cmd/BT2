### Title
Missing Zero-Address Validation in `change_reward_address` Enables Permanent Destruction of Unclaimed Yield — (`src/pool/pool.cairo`)

---

### Summary

The `change_reward_address` function in the pool contract accepts any `ContractAddress` as the new reward destination, including the zero address. A pool member who sets their reward address to zero will have all future reward claims silently transferred to address zero (burned), permanently destroying their unclaimed yield with no recovery path.

---

### Finding Description

`change_reward_address` in `src/pool/pool.cairo` performs only one validation: it checks that the new address is not the token contract address. [1](#0-0) 

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

    // Update reward_address and commit to storage.
    pool_member_info.reward_address = reward_address;
    self.write_pool_member_info(:pool_member, :pool_member_info);
    ...
}
```

There is no `assert!(reward_address.is_non_zero(), ...)` guard. The zero address (`0x0`) passes the only existing check because it is not the token contract address.

The same omission exists in the staking contract's `change_reward_address`: [2](#0-1) 

Once the reward address is set to zero, every downstream reward-transfer path routes funds to address zero. In the pool contract, `claim_rewards` calls `checked_transfer(recipient: reward_address, ...)` where `reward_address` is now zero: [3](#0-2) 

On Starknet, the STRK ERC-20 implementation does not reject transfers to the zero address; the transfer succeeds and the tokens are burned. There is no mechanism to recover a reward address once it has been committed to storage, and no mechanism to reclaim burned tokens.

The spec confirms the only precondition for `change_reward_address` is pool-member existence and that the address is not the token address — zero address is explicitly not listed as an error case: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing / destruction of unclaimed yield.**

A pool member who accidentally (or deliberately, as a self-harm) calls `change_reward_address(0)` will have all accrued and future rewards transferred to address zero on every subsequent `claim_rewards` call. The tokens are permanently unrecoverable. The pool member's principal (delegation amount) is unaffected, but all yield is irreversibly destroyed. This maps directly to the allowed impact: *"Permanent freezing of unclaimed yield."*

---

### Likelihood Explanation

**Low-Medium.** The call is permissionless for any registered pool member. A single mistaken transaction (e.g., passing an uninitialized variable, a UI bug, or a scripting error that serializes `0` instead of a real address) is sufficient to trigger the loss. No privileged role, no bridge compromise, and no external dependency is required. The entry path is fully reachable by an unprivileged delegator.

---

### Recommendation

Add a non-zero guard at the top of `change_reward_address` in both `src/pool/pool.cairo` and `src/staking/staking.cairo`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::REWARD_ADDRESS_IS_ZERO);
```

This mirrors the fix applied in the referenced report (validating that the new address is a live contract/non-zero value before committing it to storage).

---

### Proof of Concept

1. Pool member `Alice` has 1000 STRK delegated and 50 STRK in unclaimed rewards.
2. Alice calls `pool.change_reward_address(reward_address: 0)`.
   - The only check (`token_address != 0`) passes.
   - `pool_member_info.reward_address` is written as `0`.
3. Alice (or anyone) calls `pool.claim_rewards(pool_member: Alice)`.
   - The contract reads `reward_address = 0` from storage.
   - It calls `token.checked_transfer(recipient: 0, amount: 50_STRK)`.
   - The ERC-20 transfer to address zero succeeds; 50 STRK are burned.
4. Alice's `unclaimed_rewards` is reset to zero. The 50 STRK are permanently gone.
5. Every future epoch's rewards for Alice will be burned in the same way until she exits the pool — but she cannot change her reward address back to a valid address without calling `change_reward_address` again (which she can do, but only after the damage is done for any rewards already accrued while the address was zero).

### Citations

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

**File:** src/staking/staking.cairo (L517-540)
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

            // Emit event.
            self
                .emit(
                    Events::StakerRewardAddressChanged {
                        staker_address, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** docs/spec.md (L2117-2136)
```markdown
### change_reward_address
```rust
fn change_reward_address(
  ref self: ContractState,
  reward_address: ContractAddress
)
```
#### description <!-- omit from toc -->
Change the reward address for a pool member.
#### emits <!-- omit from toc -->
1. [Pool Member Reward Address Changed](#pool-member-reward-address-changed)
#### errors <!-- omit from toc -->
1. [POOL\_MEMBER\_DOES\_NOT\_EXIST](#pool_member_does_not_exist)
2. [REWARD\_ADDRESS\_IS\_TOKEN](#reward_address_is_token)
#### pre-condition <!-- omit from toc -->
1. Pool member exist in the contract.
#### access control <!-- omit from toc -->
Only pool member can execute.
#### logic <!-- omit from toc -->
1. Change registered `reward_address` for the pool member.
```
