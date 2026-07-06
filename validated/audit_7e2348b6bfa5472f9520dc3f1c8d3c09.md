### Title
Zero `reward_address` Accepted Without Validation, Permanently Burning Staker and Delegator Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Both the staking and pool contracts accept a zero (`0x0`) `reward_address` without any validation. When rewards are later claimed or distributed, the STRK transfer is sent to the zero address, permanently destroying the accumulated yield. The root cause is a missing non-zero check on `reward_address` in four entry points reachable by any unprivileged staker or delegator.

---

### Finding Description

The external report's vulnerability class is **lax input validation on address parameters**: the Push Protocol snap accepted any string as an Ethereum address, including the zero address, leading to funds being routed to an uncontrolled destination. The direct analog here is that the Starknet Staking contracts accept `ContractAddress` zero as a valid `reward_address` in every path that registers or updates it.

**Entry point 1 — `stake()` in `src/staking/staking.cairo`**

The function validates that `reward_address` is not a registered token address, but performs no zero-address check: [1](#0-0) 

`reward_address = 0x0` passes this guard and is written directly into `staker_info`. [2](#0-1) 

**Entry point 2 — `change_reward_address()` in `src/staking/staking.cairo`**

The same single guard is the only check before overwriting the stored reward address: [3](#0-2) 

**Entry point 3 — `enter_delegation_pool()` in `src/pool/pool.cairo`**

A delegator supplies `reward_address` freely; only the token-address guard is present: [4](#0-3) 

**Entry point 4 — `change_reward_address()` in `src/pool/pool.cairo`**

Identical single-guard pattern for pool members: [5](#0-4) 

**Reward disbursement paths that consume the stored address**

`send_rewards_to_staker` (called by both `claim_rewards` and `unstake_action`) transfers directly to whatever is stored in `reward_address` with no further check: [6](#0-5) 

The pool's `claim_rewards` does the same: [7](#0-6) 

In Cairo / Starknet, address `0x0` is a valid felt value; the ERC-20 `checked_transfer` call does not inherently revert on a zero recipient, so the transfer succeeds and the tokens are irrecoverably sent to an address no one controls.

---

### Impact Explanation

Any staker or delegator who registers or later sets `reward_address = 0x0` will have every STRK reward payment routed to the zero address. Because `unclaimed_rewards_own` (staking) and the pool's accumulated rewards are zeroed out after the transfer, the loss is permanent — there is no recovery path once the transfer executes. This constitutes **permanent freezing (destruction) of unclaimed yield**, which maps to the High-impact category.

Additionally, `unstake_action` is callable by any address after the exit window expires: [8](#0-7) 

A third party can therefore trigger the reward burn on behalf of a staker who has already called `unstake_intent`, removing even the staker's ability to self-rescue by changing the reward address before the burn occurs.

---

### Likelihood Explanation

The likelihood is **low-to-medium**:

- A staker or delegator can supply `reward_address = 0x0` at registration time through a buggy front-end, a scripting error, or a deliberate test call that is accidentally broadcast to mainnet.
- `change_reward_address` is callable at any time, including while in the exit window, so a user who mistakenly sets it to zero just before unstaking will have their rewards burned when `unstake_action` is executed (by themselves or by any third party).
- No privileged role is required; any unprivileged staker or delegator can reach this state.

---

### Recommendation

Add an explicit non-zero assertion on `reward_address` in all four entry points:

```cairo
assert!(reward_address.is_non_zero(), "Reward address cannot be zero");
```

This mirrors the existing `CALLER_IS_ZERO_ADDRESS` guard already present in the codebase: [9](#0-8) 

Apply the same pattern to `stake()`, `change_reward_address()` in both contracts, and `enter_delegation_pool()`.

---

### Proof of Concept

```
1. Staker calls staking.stake(
       reward_address = 0x0,          // zero address — accepted, no revert
       operational_address = <valid>,
       amount = MIN_STAKE
   )

2. Attestation contract calls update_rewards_from_attestation_contract(staker_address)
   → staker_info.unclaimed_rewards_own is now > 0

3. Staker calls staking.unstake_intent()
   → exit window starts

4. After exit window, *anyone* calls staking.unstake_action(staker_address)
   → send_rewards_to_staker() executes:
        token.checked_transfer(recipient: 0x0, amount: rewards)   // rewards burned
   → staker receives principal back, but all yield is permanently lost
```

The same sequence applies to a pool member via `pool.enter_delegation_pool(reward_address: 0x0, ...)` followed by `pool.claim_rewards(pool_member)`.

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```

**File:** src/staking/staking.cairo (L334-339)
```text
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );
```

**File:** src/staking/staking.cairo (L483-496)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
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

**File:** src/pool/pool.cairo (L364-366)
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

**File:** src/staking/utils.cairo (L62-64)
```text
pub(crate) fn assert_caller_is_not_zero() {
    assert!(get_caller_address().is_non_zero(), "{}", Error::CALLER_IS_ZERO_ADDRESS);
}
```
