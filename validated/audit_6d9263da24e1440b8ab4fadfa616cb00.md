### Title
Principal Returned to `pool_member` Instead of Funding `reward_address` When `reward_address` Tops Up the Pool - (File: src/pool/pool.cairo)

### Summary
`Pool::add_to_delegation_pool` permits the `reward_address` to inject additional principal into a pool member's position, pulling tokens from the `reward_address`'s own balance. However, `Pool::exit_delegation_pool_action` unconditionally returns the entire `unpool_amount` to `pool_member`, with no mechanism to route any portion back to the `reward_address` that funded it. A pool member can therefore drain a third-party `reward_address` by topping up the position through that address and then exiting.

### Finding Description
`add_to_delegation_pool` (src/pool/pool.cairo lines 221–254) allows either `pool_member` or `pool_member_info.reward_address` to be the caller:

```
caller_address == pool_member || caller_address == pool_member_info.reward_address
```

When `reward_address` is the caller, `transfer_from_delegator` pulls tokens from `caller_address` (i.e., `reward_address`):

```
transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
```

The balance credit, however, is applied to `pool_member`, not to `caller_address`:

```
let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

When the pool member later exits via `exit_delegation_pool_action` (lines 295–333), the full `unpool_amount` is transferred to `pool_member` with no reference to who originally funded it:

```
token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
```

There is no `refundAddress` field in the pool member record, no per-funder accounting, and no way for `reward_address` to reclaim the principal it contributed.

Additionally, `change_reward_address` (lines 505–526) is callable at any time by `pool_member` alone, so a malicious pool member can:
1. Set `reward_address` to a victim address (e.g., an auto-compounding contract or a co-investor).
2. Wait for or induce the victim to call `add_to_delegation_pool` (the victim must have pre-approved the pool contract).
3. Change `reward_address` back to themselves.
4. Call `exit_delegation_pool_intent` then `exit_delegation_pool_action` to receive the victim's tokens.

### Impact Explanation
The `reward_address` permanently loses the principal it contributed. All tokens transferred via `add_to_delegation_pool` when called by `reward_address` are irrecoverably credited to `pool_member` and returned to `pool_member` on exit. This constitutes direct theft of user funds (Critical impact tier).

### Likelihood Explanation
Likelihood is low-to-medium. The precondition is that `reward_address` must have granted ERC-20 approval to the pool contract and must call `add_to_delegation_pool`. This is a realistic scenario for:
- Auto-compounding smart contracts that receive rewards and re-stake them on behalf of a pool member.
- Custodial or co-investment arrangements where a separate treasury address tops up a delegator's position.

In both cases the `reward_address` entity may not be aware that the principal return path is hardcoded to `pool_member`.

### Recommendation
Add a `refund_address` field to the pool member record (or track per-funder contributions) so that principal contributed by `reward_address` is returned to `reward_address` on exit, mirroring the pattern suggested in the referenced report. At minimum, document clearly that any tokens added by `reward_address` via `add_to_delegation_pool` will be returned to `pool_member`, not to `reward_address`, so that integrators are not surprised.

### Proof of Concept
1. Alice deploys an auto-compounding contract `AutoComp` and registers as a pool member with `reward_address = AutoComp`.
2. `AutoComp` receives STRK rewards, approves the pool contract, and calls `add_to_delegation_pool(pool_member: Alice, amount: R)` — `R` tokens leave `AutoComp`'s balance and are credited to Alice's position.
3. Alice calls `change_reward_address(reward_address: Alice)` — `AutoComp` is no longer the reward address.
4. Alice calls `exit_delegation_pool_intent(amount: original + R)`.
5. After the exit window, Alice calls `exit_delegation_pool_action(pool_member: Alice)`.
6. Alice receives `original + R` tokens; `AutoComp` has lost `R` tokens with no recourse.

Root cause: [1](#0-0)  — funds are pulled from `caller_address` (which may be `reward_address`) but the balance is credited to `pool_member`.

Exit path: [2](#0-1)  — principal is unconditionally returned to `pool_member` with no awareness of who funded it.

`change_reward_address` access control (pool member only, no timelock): [3](#0-2)

### Citations

**File:** src/pool/pool.cairo (L227-238)
```text
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
```

**File:** src/pool/pool.cairo (L328-330)
```text
            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
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
