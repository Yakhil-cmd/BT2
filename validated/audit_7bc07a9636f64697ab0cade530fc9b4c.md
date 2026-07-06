### Title
Staker and Pool Member Can Set `reward_address` to Zero Address, Causing Permanent Freezing of Unclaimed Yield — (`src/staking/staking.cairo`, `src/pool/pool.cairo`)

---

### Summary
Both `stake()` and `change_reward_address()` in `staking.cairo`, and the corresponding pool entry/reward-address paths in `pool.cairo`, accept any `ContractAddress` for `reward_address` with only a single guard: that the address is not a registered token. There is no check that `reward_address` is non-zero. When `claim_rewards()` is later called, the contract unconditionally transfers accumulated STRK rewards to whatever `reward_address` is stored — including address `0`. Tokens sent to address `0` on Starknet are permanently inaccessible, freezing all unclaimed yield for that staker or pool member.

---

### Finding Description

**`stake()` — `src/staking/staking.cairo` lines 288–317**

```cairo
fn stake(
    ref self: ContractState,
    reward_address: ContractAddress,   // ← accepted without zero-check
    operational_address: ContractAddress,
    amount: Amount,
) {
    ...
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,   // only guard
    );
```

No `assert!(reward_address.is_non_zero(), ...)` is present.

**`change_reward_address()` — `src/staking/staking.cairo` lines 517–540**

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,   // only guard
    );
```

Again, no zero-address guard. A staker who already holds accumulated `unclaimed_rewards_own` can call this at any time to redirect future (and immediate) reward claims to address `0`.

**`send_rewards_to_staker()` / `claim_rewards()` — `src/staking/staking.cairo` line 1625**

```cairo
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

The transfer executes unconditionally against whatever `reward_address` is stored.

**Pool `claim_rewards()` — `src/pool/pool.cairo` line 366**

```cairo
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

The same pattern exists for pool members: `enter_delegation_pool` and `change_reward_address` in `pool.cairo` carry no zero-address guard, and `claim_rewards` transfers directly to the stored `reward_address`.

---

### Impact Explanation

Any staker or pool member who registers or later changes their `reward_address` to `0x0` will have all future reward claims transferred to the zero address. On Starknet, address `0` is not controlled by any key; tokens sent there are permanently inaccessible. This constitutes **permanent freezing of unclaimed yield** for the affected participant. The staking principal itself is returned to `staker_address` on `unstake_action`, so principal is not at risk — only accumulated rewards are frozen.

Impact: **High** — matches "Permanent freezing of unclaimed yield or unclaimed royalties."

---

### Likelihood Explanation

A staker or pool member must explicitly supply `reward_address = 0` either at `stake()` time or via a subsequent `change_reward_address()` call. This is unlikely through a well-built front-end but is trivially achievable via direct contract interaction. The external report's analogous finding was also rated low-likelihood for the same reason ("most users will interact directly through the front-end application where misconfiguration is highly unlikely"), yet was accepted as Medium/High. Here the entry path is fully permissionless and requires no privileged role.

Likelihood: **Low**.

---

### Recommendation

Add a non-zero assertion for `reward_address` in every function that writes it:

```cairo
// In stake(), change_reward_address() (staking.cairo)
// and enter_delegation_pool(), change_reward_address() (pool.cairo):
assert!(reward_address.is_non_zero(), "{}", Error::REWARD_ADDRESS_IS_ZERO);
```

This mirrors the fix applied in the referenced report (`if (trustedRemote == 0) revert()`).

---

### Proof of Concept

1. Attacker (staker) calls `stake(reward_address: 0, operational_address: <valid>, amount: min_stake)`.
   - Passes the only guard: `does_token_exist(0)` returns `false`.
   - Staker is registered with `reward_address = 0`.
2. Epochs advance; the attestation contract credits `unclaimed_rewards_own` to the staker.
3. Anyone calls `claim_rewards(staker_address: attacker)`.
   - `send_rewards_to_staker` executes `checked_transfer(recipient: 0, amount: rewards)`.
   - Tokens are transferred to address `0` and are permanently inaccessible.
4. Alternatively, an existing staker with accrued rewards calls `change_reward_address(reward_address: 0)` and then `claim_rewards` — same outcome.
5. The identical path exists for pool members via `pool.cairo`'s `claim_rewards`.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L307-311)
```text
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
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

**File:** src/staking/staking.cairo (L1621-1626)
```text
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/pool/pool.cairo (L364-366)
```text
            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```
