### Title
Missing Zero-Address Validation on `reward_address` Enables Permanent Loss of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary

Both the staking and pool contracts accept a zero address as a valid `reward_address` in `stake`, `enter_delegation_pool`, `change_reward_address` (staking), and `change_reward_address` (pool). No zero-address check is performed before storing or using the value. When rewards are later transferred to a zero `reward_address`, they are either permanently burned (if the ERC20 permits zero-address transfers) or the transfer reverts, causing `claim_rewards` and `unstake_action` to revert and temporarily freezing the staker's principal until the address is corrected.

---

### Finding Description

**Root cause — `change_reward_address` in `staking.cairo`:**

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← NO assert!(reward_address.is_non_zero(), ...)
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    staker_info.reward_address = reward_address;   // zero stored
    self.write_staker_info(:staker_address, :staker_info);
``` [1](#0-0) 

The only guard is `REWARD_ADDRESS_IS_TOKEN`, which passes for `0x0` since zero is not a registered token address.

**Same gap in `stake`:** [2](#0-1) 

**Same gap in `pool.cairo` — `change_reward_address`:**

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    // ← NO zero check
    pool_member_info.reward_address = reward_address;
``` [3](#0-2) 

**Same gap in `enter_delegation_pool`:** [4](#0-3) 

**Downstream sink — `send_rewards_to_staker`:**

```cairo
fn send_rewards_to_staker(...) {
    let reward_address = staker_info.reward_address;   // may be 0x0
    let amount = staker_info.unclaimed_rewards_own;
    claim_from_reward_supplier(...);
    token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [5](#0-4) 

`unstake_action` calls `send_rewards_to_staker` before returning the principal, so a revert here locks the staker's entire balance. [6](#0-5) 

**Pool rewards sink — `claim_rewards` in `pool.cairo`:**

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [7](#0-6) 

---

### Impact Explanation

**Path A — ERC20 allows zero-address transfers (burn):**
Rewards are silently transferred to `0x0` and permanently destroyed. Every `claim_rewards` call succeeds but yields nothing to the user. This is **permanent freezing of unclaimed yield** (High).

**Path B — ERC20 reverts on zero-address transfers (standard OpenZeppelin behaviour):**
`claim_rewards` reverts. More critically, `unstake_action` also reverts because it calls `send_rewards_to_staker` before returning the principal. The staker's entire staked principal is inaccessible until they call `change_reward_address` with a valid address. This is **temporary freezing of funds** (High). Note that `change_reward_address` has no guard against being called while `unstake_time` is set, so recovery is possible — but only if the user realises the cause. [8](#0-7) 

---

### Likelihood Explanation

Any staker or pool member can trigger this by passing `0x0` as `reward_address` at registration time or via `change_reward_address`. No privileged role is required. The likelihood of accidental misconfiguration is non-trivial given that zero is the default/unset value in many tooling contexts. Intentional self-harm is also possible (e.g., a staker who later wants to grief their own delegators by locking pool reward flows). Likelihood: **Low-Medium**.

---

### Recommendation

Add an explicit non-zero guard in every function that accepts or stores a `reward_address`:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply this to:
- `stake` in `staking.cairo`
- `change_reward_address` in `staking.cairo`
- `enter_delegation_pool` in `pool.cairo`
- `change_reward_address` in `pool.cairo`

The `GenericError::ZERO_ADDRESS` variant already exists in the shared error catalogue. [9](#0-8) 

---

### Proof of Concept

**Staker variant:**
1. Staker calls `stake(reward_address: 0x0, operational_address: X, amount: min_stake)`. No revert — zero passes the `REWARD_ADDRESS_IS_TOKEN` check.
2. Staker accumulates `unclaimed_rewards_own > 0` via attestation/consensus rewards.
3. Staker calls `unstake_intent()`.
4. After `exit_wait_window`, staker calls `unstake_action()`.
5. `unstake_action` → `send_rewards_to_staker` → `checked_transfer(recipient: 0x0, amount: rewards)`.
   - If ERC20 burns: rewards gone, principal returned.
   - If ERC20 reverts: entire `unstake_action` reverts; principal locked until `change_reward_address` is called with a valid address.

**Pool member variant:**
1. Pool member calls `enter_delegation_pool(reward_address: 0x0, amount: X)`.
2. Pool member accumulates rewards.
3. Pool member calls `claim_rewards` → `checked_transfer(recipient: 0x0, amount: rewards)` → burn or revert.

### Citations

**File:** src/staking/staking.cairo (L307-317)
```text
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

**File:** src/staking/staking.cairo (L1619-1626)
```text
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/pool/pool.cairo (L191-206)
```text
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

**File:** src/pool/pool.cairo (L365-366)
```text
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

**File:** src/errors.cairo (L20-20)
```text
    ZERO_ADDRESS,
```
