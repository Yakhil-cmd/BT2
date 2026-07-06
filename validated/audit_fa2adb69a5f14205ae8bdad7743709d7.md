### Title
Missing Zero-Address Validation on `reward_address` Allows Storing Invalid State and Freezing Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
The `stake`, `change_reward_address` (staking), and `change_reward_address` (pool) functions accept a `reward_address` parameter and persist it to storage without validating it is non-zero. This is the direct analog of the `OpenOraclePriceData.put` bug: a caller-supplied address is used to update protocol state without a zero-address guard, allowing invalid state to be committed. When rewards are later claimed, the transfer to the zero address either permanently destroys the tokens or causes `claim_rewards` to revert, freezing the staker's or pool member's unclaimed yield.

---

### Finding Description

**`stake` — `src/staking/staking.cairo`** [1](#0-0) 

The only guard on `reward_address` is a token-address check. There is no `assert!(reward_address.is_non_zero(), ...)` guard. A staker may call `stake(reward_address: 0, ...)` and the zero address is written directly into `InternalStakerInfoV1.reward_address`. [2](#0-1) 

**`change_reward_address` — `src/staking/staking.cairo`** [3](#0-2) 

Same pattern: only the token-address check is present; zero address passes silently and is written to storage.

**`change_reward_address` — `src/pool/pool.cairo`** [4](#0-3) 

The pool variant checks only that `reward_address != token_address`. Zero address is accepted and stored as the pool member's reward address.

---

### Impact Explanation

When `claim_rewards` is later invoked, the staking contract calls `checked_transfer` (or equivalent) to `reward_address`. OpenZeppelin Cairo ERC20 rejects transfers to the zero address with a panic, causing `claim_rewards` to revert unconditionally. The staker's or pool member's accumulated unclaimed yield becomes inaccessible until they issue a corrective `change_reward_address` call — constituting **temporary freezing of unclaimed yield** (High). If the underlying ERC20 does not guard against zero-address transfers, the tokens are sent to the zero address and **permanently destroyed** (also High).

---

### Likelihood Explanation

Any staker or pool member — unprivileged callers — can trigger this by passing `ContractAddress` zero to `stake` or `change_reward_address`. The path requires no privileged role, no bridge compromise, and no external dependency. Accidental invocation (e.g., a front-end bug, a scripting error, or a default-initialized variable) is realistic. The function succeeds without error, giving no indication that invalid state was stored, exactly mirroring the original `ecrecover`-zero-address silent-failure pattern.

---

### Recommendation

Add an explicit non-zero assertion on `reward_address` at the top of each affected function, before any state is written:

```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

This mirrors the fix suggested in the original report: fail early and predictably rather than committing invalid state.

---

### Proof of Concept

1. Deploy the staking system.
2. Call `stake(reward_address: 0, operational_address: <valid>, amount: <min_stake>)` — transaction succeeds; staker is registered with `reward_address = 0`.
3. Advance epochs; attestation accrues rewards.
4. Call `claim_rewards(staker_address: <staker>)` — transaction reverts because the ERC20 transfer to address `0` is rejected, or tokens are sent to the zero address and destroyed.
5. The staker's unclaimed yield is frozen (or destroyed) with no protocol-level error having been raised at the point of the invalid write. [5](#0-4) [3](#0-2) [4](#0-3)

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

**File:** src/staking/staking.cairo (L334-339)
```text
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );
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

**File:** src/pool/pool.cairo (L505-510)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
```
