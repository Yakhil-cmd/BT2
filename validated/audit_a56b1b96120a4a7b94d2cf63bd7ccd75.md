### Title
Single-Step Reward Address Change Without Confirmation Allows Permanent Loss of Unclaimed Yield - (File: src/staking/staking.cairo)

### Summary
Both `Staking` and `Pool` contracts expose a `change_reward_address` function that immediately overwrites the reward destination in a single transaction. No confirmation from the new address is required, and no zero-address guard exists. A staker or pool member who mistypes the new address will have all subsequent reward claims routed to an uncontrolled address, permanently losing those funds.

### Finding Description
`Staking::change_reward_address` (staking.cairo line 517) and `Pool::change_reward_address` (pool.cairo line 505) both follow the same pattern:

1. Assert the new address is not a registered token address.
2. Overwrite `staker_info.reward_address` / `pool_member_info.reward_address` immediately.
3. Emit an event.

There is no check that the new address is non-zero, no pending-acceptance state, and no way for the protocol to verify the caller controls the destination.

```cairo
// staking.cairo:517-531
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}", GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    let staker_address = get_caller_address();
    let mut staker_info = self.internal_staker_info(:staker_address);
    staker_info.reward_address = reward_address;   // immediate, no confirmation
    self.write_staker_info(:staker_address, :staker_info);
    ...
}
```

All reward disbursement paths read `staker_info.reward_address` directly and transfer to it:

- `send_rewards_to_staker` (staking.cairo line 1625): `token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into())`
- `Pool::claim_rewards` (pool.cairo line 366): `reward_token.checked_transfer(recipient: reward_address, amount: rewards.into())`

Once rewards are transferred to the wrong address, they are irrecoverable. The staker can call `change_reward_address` again to fix the stored value, but any rewards already claimed (or claimed by anyone during the window) are gone.

The spec confirms the only validation is `REWARD_ADDRESS_IS_TOKEN`; there is no `ZERO_ADDRESS` guard for this path (docs/spec.md line 2843–2844 lists only `REWARD_ADDRESS_IS_TOKEN` as the relevant error).

### Impact Explanation
**High – Permanent freezing / theft of unclaimed yield.**

If a staker or pool member sets the reward address to:
- An address they do not control (typo, copy-paste error): all rewards claimed after that point are transferred to a third party.
- The zero address (0x0): `checked_transfer` to zero will either revert (freezing the ability to claim) or succeed (burning the tokens), both resulting in permanent loss.

The staker's principal (staked STRK) is unaffected; only accumulated yield is at risk. This maps directly to the allowed impact "Permanent freezing of unclaimed yield or unclaimed royalties."

### Likelihood Explanation
**Medium.** Address management errors are among the most common user mistakes in blockchain protocols. The function is callable by any registered staker or pool member at any time without a time-lock or cooldown. There is no off-chain UI requirement; the function is directly callable on-chain. The absence of a zero-address guard makes the accidental-burn path trivially reachable.

### Recommendation
Implement a two-step commit-accept pattern:

1. **Propose**: The staker calls `propose_reward_address(new_address)`, which stores a pending value but does not activate it.
2. **Accept**: The new address calls `accept_reward_address()`, which moves the pending value into the active `reward_address`.

This ensures the new address is live and controlled before rewards are routed to it. At minimum, add a zero-address guard:
```cairo
assert!(reward_address.is_non_zero(), "{}", GenericError::ZERO_ADDRESS);
```

Apply the same fix to `Pool::change_reward_address`.

### Proof of Concept
1. Alice is a registered staker with 1 000 000 STRK staked and `reward_address = 0xAlice`.
2. Alice intends to update her reward address to `0xAliceNew` but mistypes `0xAliceTypo`.
3. Alice calls `staking.change_reward_address(0xAliceTypo)`. The call succeeds immediately.
4. Several epochs pass; attestations are submitted; `unclaimed_rewards_own` accumulates.
5. Anyone calls `staking.claim_rewards(alice_staker_address)`.
6. `send_rewards_to_staker` executes `checked_transfer(recipient: 0xAliceTypo, amount: rewards)`.
7. Rewards are permanently transferred to `0xAliceTypo`, an address Alice does not control.
8. Alice can call `change_reward_address` again to restore a correct address, but the already-claimed rewards are irrecoverable.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
