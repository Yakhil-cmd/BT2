### Title
Arbitrary STRK Deposits via StarkGate to `RewardSupplier` Are Permanently Frozen — (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `on_receive` callback in `RewardSupplier` intentionally accepts STRK deposits from **any** L1 depositor via StarkGate, but only decrements the accounting variable `l1_pending_requested_amount`. It never credits `unclaimed_rewards`. Because `claim_rewards` is strictly bounded by `unclaimed_rewards`, any tokens deposited by an arbitrary sender are permanently locked in the contract with no recovery path.

---

### Finding Description

`on_receive` is the StarkGate deposit callback. The code explicitly acknowledges the permissive design:

```
// Note that the deposit can be done by anyone (not just the L1 reward supplier), so
// depositor is not checked.
``` [1](#0-0) 

The function validates only that the **caller** is StarkGate and that the token is STRK, then decrements `l1_pending_requested_amount`: [2](#0-1) 

Critically, `unclaimed_rewards` is **never touched** inside `on_receive`. It is only ever increased by `update_unclaimed_rewards_from_staking_contract` (called exclusively by the staking contract): [3](#0-2) 

`claim_rewards` enforces a hard ceiling of `unclaimed_rewards` before transferring tokens: [4](#0-3) 

Any tokens that arrive in the contract's ERC-20 balance beyond what `unclaimed_rewards` accounts for can never be transferred out. There is no sweep, rescue, or admin-withdrawal function anywhere in the contract.

---

### Impact Explanation

Any STRK tokens bridged to the `RewardSupplier` address by an arbitrary depositor are **permanently frozen**. The depositor's tokens sit in the contract's ERC-20 balance but are invisible to `claim_rewards`, which only reads `unclaimed_rewards`. There is no code path that can recover them.

A secondary effect: the arbitrary deposit reduces `l1_pending_requested_amount` (potentially to zero). If `request_funds` uses `l1_pending_requested_amount` to avoid duplicate L1 requests, a subsequent legitimate call to `update_unclaimed_rewards_from_staking_contract` may trigger a **redundant L1 mint request** for tokens that are already present in the balance, causing additional tokens to be minted and bridged — those too will be stuck, compounding the freeze.

Impact classification: **Medium — Griefing with no profit motive but damage to users or protocol** (permanent freezing of depositor funds; potential unnecessary L1 minting).

---

### Likelihood Explanation

- StarkGate allows any L1 address to bridge STRK to any L2 contract address.
- An integrator, script, or user who mistakenly targets the `RewardSupplier` address instead of the staking contract will permanently lose funds.
- A deliberate attacker can exploit this to grief the protocol's L1 minting accounting at the cost of their own tokens.
- Likelihood: **Low-Medium** (accidental misrouting is realistic; deliberate griefing is cheap relative to damage).

---

### Recommendation

Check that the depositor is the expected L1 reward supplier address, mirroring the fix suggested in the external report (restrict by sender rather than by a boolean flag):

```cairo
fn on_receive(..., depositor: EthAddress, ...) -> bool {
    assert!(
        get_caller_address() == self.starkgate_address.read(),
        "{}", Error::ON_RECEIVE_NOT_FROM_STARKGATE,
    );
    assert!(
        l2_token == self.token_dispatcher.contract_address.read(),
        "{}", Error::UNEXPECTED_TOKEN,
    );
    // ADD: restrict depositor to the known L1 reward supplier
    assert!(
        depositor == self.l1_reward_supplier.read(),
        "{}", Error::UNEXPECTED_DEPOSITOR,
    );
    ...
}
```

Alternatively, if permissive deposits are intentional, add a reconciliation step that credits any surplus balance into `unclaimed_rewards` so the tokens are not permanently frozen.

---

### Proof of Concept

1. Deploy the system normally. Note `reward_supplier` contract address on L2.
2. From any L1 account (not the L1 `RewardSupplier`), call `StarkGate.depositWithMessage(strk, amount, reward_supplier_l2_address, message)`.
3. StarkGate calls `on_receive` on the L2 `RewardSupplier`. The call succeeds (depositor is not checked).
4. `l1_pending_requested_amount` is decremented; `unclaimed_rewards` is unchanged.
5. Observe: `token.balance_of(reward_supplier) > unclaimed_rewards`.
6. Call `claim_rewards` for the full `unclaimed_rewards` amount — it succeeds and drains exactly `unclaimed_rewards`.
7. Observe: `token.balance_of(reward_supplier) == deposited_amount` — the depositor's tokens are permanently stuck with no callable function able to retrieve them. [5](#0-4) [6](#0-5)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L189-202)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );

            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L213-219)
```text
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
```

**File:** src/reward_supplier/reward_supplier.cairo (L222-255)
```text
        fn on_receive(
            ref self: ContractState,
            l2_token: ContractAddress,
            amount: u256,
            depositor: EthAddress,
            message: Span<felt252>,
        ) -> bool {
            // Note that the deposit can be done by anyone (not just the L1 reward supplier), so
            // depositor is not checked.

            // These messages accepted only from the token bridge.
            assert!(
                get_caller_address() == self.starkgate_address.read(),
                "{}",
                Error::ON_RECEIVE_NOT_FROM_STARKGATE,
            );
            // The bridge may serve multiple tokens, only the correct token may be received.
            assert!(
                l2_token == self.token_dispatcher.contract_address.read(),
                "{}",
                Error::UNEXPECTED_TOKEN,
            );
            let amount_u128: Amount = amount
                .try_into()
                .expect_with_err(GenericError::AMOUNT_TOO_HIGH);
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            if amount_u128 > l1_pending_requested_amount {
                self.l1_pending_requested_amount.write(Zero::zero());
            } else {
                l1_pending_requested_amount -= amount_u128;
                self.l1_pending_requested_amount.write(l1_pending_requested_amount);
            }
            true
        }
```

**File:** src/reward_supplier/interface.cairo (L56-76)
```text
    /// Callback function for StarkGate deposit.
    ///
    /// Notifies the contract that a transfer of `amount` from L1 via StarkGate has occurred and
    /// returns `true` upon success.
    /// This function reverts only if `amount` exceeds 2**128 FRI, which is highly unlikely.
    ///
    /// #### Errors:
    /// -
    /// [`ON_RECEIVE_NOT_FROM_STARKGATE`](staking::reward_supplier::errors::Error::ON_RECEIVE_NOT_FROM_STARKGATE)
    /// - [`UNEXPECTED_TOKEN`](staking::reward_supplier::errors::Error::UNEXPECTED_TOKEN)
    /// - [`AMOUNT_TOO_HIGH`](staking::errors::GenericError::AMOUNT_TOO_HIGH)
    ///
    /// #### Access control:
    /// Only StarkGate.
    fn on_receive(
        ref self: TContractState,
        l2_token: ContractAddress,
        amount: u256,
        depositor: EthAddress,
        message: Span<felt252>,
    ) -> bool;
```
