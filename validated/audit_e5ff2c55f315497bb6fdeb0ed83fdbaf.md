### Title
Any caller can force token delivery to an unprepared pool-member contract via `exit_delegation_pool_action`, risking permanent fund freeze - (File: src/pool/pool.cairo)

---

### Summary

`exit_delegation_pool_action` in `pool.cairo` carries no access-control check. Any address can call it for any pool member whose exit window has elapsed, unconditionally pushing the delegated tokens to the `pool_member` address. If that address is a smart contract (e.g., a vault, yield aggregator, or multisig) that has no mechanism to receive or re-route an unexpected ERC-20 credit, the funds are permanently locked. The same pattern exists in `unstake_action` in `staking.cairo`, which any caller can trigger to push both the staker's principal and accrued rewards to `staker_address` / `reward_address`.

---

### Finding Description

**Root cause — `exit_delegation_pool_action` (pool.cairo)**

The function signature accepts an arbitrary `pool_member` address and contains zero caller-identity checks:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... no caller check ...
    token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
    unpool_amount
}
```

The spec explicitly documents this: *"Any address can execute."*

The only preconditions are (1) the pool member exists, (2) an exit intent was previously filed, and (3) the exit window has elapsed. Once those are satisfied, any third party can trigger the irreversible ERC-20 push to `pool_member`.

**Root cause — `unstake_action` (staking.cairo)**

The same pattern applies at the staker level:

```cairo
fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
    // no caller check
    self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
    token_dispatcher.checked_transfer(recipient: staker_address, amount: staker_amount.into());
    ...
}
```

`send_rewards_to_staker` pushes accumulated STRK rewards to `staker_info.reward_address`, and the principal is pushed to `staker_address`. Both destinations can be arbitrary smart contracts.

**Why this matters**

DeFi protocols that integrate with the delegation pool (e.g., liquid-staking wrappers, yield aggregators, DAO treasuries) will register their own contract address as `pool_member`. Such contracts typically track internal accounting state (shares, indices, balances). An unexpected ERC-20 credit arriving outside the contract's own controlled flow can:

1. **Permanently lock funds** — if the contract has no withdrawal path for tokens received outside its normal flow.
2. **Corrupt internal accounting** — if the contract's share/index math assumes it controls all token inflows, the surprise credit inflates the apparent pool balance, diluting or mis-attributing rewards to existing participants.

Neither the pool contract nor the staking contract implements any callback or hook (analogous to `onStreamWithdrawn` in Sablier or `onERC721Received` in ERC-721) that would let the recipient contract react to or reject the forced delivery.

---

### Impact Explanation

**Severity: High — Temporary or Permanent Freezing of Funds**

If `pool_member` (or `staker_address` / `reward_address`) is a smart contract without a token-recovery path, the forced ERC-20 transfer permanently locks the delegated principal inside that contract. The amount at risk equals the full `unpool_amount` of the pool member, which can be arbitrarily large. This matches the allowed impact: *"Temporary freezing of funds"* / *"Permanent freezing of unclaimed yield or unclaimed royalties"*.

---

### Likelihood Explanation

**Low-Medium.** The scenario requires the pool member to be a smart contract that cannot handle an unexpected ERC-20 credit. This is increasingly realistic as:

- Liquid-staking protocols and DAO treasuries are the primary integrators of delegation pools.
- Such contracts commonly track internal accounting that assumes they control all token inflows.
- The attacker needs no special privilege — only knowledge of the pool member's address and patience to wait for the exit window to expire.

---

### Recommendation

1. **Restrict `exit_delegation_pool_action` to the pool member only** (mirror the access control already applied to `exit_delegation_pool_intent`):
   ```cairo
   assert!(get_caller_address() == pool_member, "...");
   ```
2. **Optionally implement a recipient hook** — after the transfer, attempt a call to an `IPoolMemberReceiver` interface on `pool_member` (if it is a contract), allowing it to react to the credit. Make the hook optional so EOAs are unaffected.
3. Apply the same fix to `unstake_action` in `staking.cairo` — restrict it to `staker_address` or `reward_address`, or at minimum document the risk prominently for integrators.

---

### Proof of Concept

1. A liquid-staking protocol (`VaultContract`) deploys and registers itself as a pool member in a delegation pool, delegating user funds.
2. `VaultContract` calls `exit_delegation_pool_intent(amount)` to begin the exit process. Its internal state now expects to receive tokens only when it calls `exit_delegation_pool_action` itself (e.g., after updating its own accounting).
3. The exit window elapses.
4. An attacker (any EOA) calls `pool.exit_delegation_pool_action(pool_member: VaultContract_address)`.
5. The pool contract executes `token_dispatcher.checked_transfer(recipient: VaultContract_address, amount: unpool_amount)` — the tokens land in `VaultContract` without any accounting update inside `VaultContract`.
6. `VaultContract`'s share-price calculation is now inflated (or the tokens are simply untracked), and if `VaultContract` has no recovery function, the funds are permanently locked.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/interface.cairo (L86-106)
```text
    /// Completes a pending exit for the given pool member once the required waiting period has
    /// passed.
    /// Sends the withdrawn funds to `pool_member` and returns the transferred amount.
    ///
    /// #### Preconditions:
    /// - `pool_member` exists and requested to exit.
    /// - The exit window for `pool_member` has elapsed.
    ///
    /// #### Emits:
    /// - [`PoolMemberExitAction`](Events::PoolMemberExitAction)
    ///
    /// #### Errors:
    /// - [`POOL_MEMBER_DOES_NOT_EXIST`](staking::pool::errors::Error::POOL_MEMBER_DOES_NOT_EXIST)
    /// - [`MISSING_UNDELEGATE_INTENT`](staking::errors::GenericError::MISSING_UNDELEGATE_INTENT)
    /// - [`INTENT_WINDOW_NOT_FINISHED`](staking::errors::GenericError::INTENT_WINDOW_NOT_FINISHED)
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::remove_from_delegation_pool_action`]
    fn exit_delegation_pool_action(
        ref self: TContractState, pool_member: ContractAddress,
    ) -> Amount;
```

**File:** src/staking/staking.cairo (L483-515)
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
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
```

**File:** src/staking/staking.cairo (L1614-1629)
```text
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
        }
```

**File:** docs/spec.md (L702-709)
```markdown
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
1. Claim rewards.
2. Remove funds and transfer to staker.
3. Transfer pool stake to delegation pool contract.
4. Call [set\_staker\_removed](#set_staker_removed) on the delegation_pool_contract.
5. Delete staker record.
```

**File:** docs/spec.md (L1999-2004)
```markdown
3. Staking contract is unpaused.
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
1. [Remove from delegation pool action](#remove_from_delegation_pool_action).
2. Transfer funds to pool member.
```
