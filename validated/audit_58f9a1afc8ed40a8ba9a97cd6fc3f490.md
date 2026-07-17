### Title
Relayer Deposit Stolen via Intentionally Failing Meta-Transaction Inner Receipt — (`runtime/runtime/src/actions.rs`)

### Summary

In NEAR's meta-transaction (`DelegateAction`) system, the relayer pays the deposit for inner actions, but when an inner receipt fails on the receiver's shard, the deposit refund is sent to the **sender** (Alice), not the **relayer** who paid it. An unprivileged user can deliberately craft a `DelegateAction` with a large deposit that will fail on the receiver's shard, causing the relayer to lose the deposit while the user gains it — a direct, protocol-enforced theft with no relayer defense.

### Finding Description

When `apply_delegate_action` processes a `DelegateAction`, it creates a new inner receipt with `predecessor_id: sender_id.clone()` — Alice's account ID, not the relayer's. [1](#0-0) 

The relayer (signer of the outer transaction) pays the deposit for all inner actions, as confirmed by the inline comment: [2](#0-1) 

When the inner receipt fails on the receiver's shard, `refund_unspent_gas_and_deposits` computes `deposit_refund = total_deposit` and routes it to `receipt.balance_refund_receiver()`: [3](#0-2) [4](#0-3) 

`balance_refund_receiver()` returns the receipt's `predecessor_id` — which is Alice, not the relayer: [5](#0-4) 

The protocol documentation explicitly acknowledges this broken invariant: [6](#0-5) 

**Attack path:**
1. Alice signs a `DelegateAction` containing a `FunctionCallAction` or `TransferAction` with a large `deposit` (e.g., 100 NEAR) targeting a receiver contract she knows will reject the call (non-existent method, panicking contract, etc.).
2. Alice submits the `SignedDelegateAction` off-chain to a relayer.
3. The relayer wraps it in a transaction and submits it on-chain, paying the 100 NEAR deposit from its own balance.
4. On Alice's shard, `apply_delegate_action` validates the signature and nonce, then emits the inner receipt with `predecessor_id = Alice`.
5. On the receiver's shard, the inner receipt fails. `refund_unspent_gas_and_deposits` sends the 100 NEAR deposit refund to `predecessor_id` = Alice.
6. Alice has received 100 NEAR; the relayer has lost 100 NEAR.

The relayer cannot prevent this after submission. The only mitigation suggested by the code is off-chain pre-verification of the `DelegateAction` content — but Alice can arrange for the failure to occur only after the relayer has committed (e.g., by draining the target contract's state between relayer verification and on-chain execution).

### Impact Explanation

**Accounting invariant broken:** The party who pays a deposit (relayer) does not receive the refund when the action fails; instead the deposit is transferred to an unprivileged user (Alice) who paid nothing. The corrupted value is the `deposit` field of the inner `FunctionCallAction` or `TransferAction` — up to the maximum deposit Alice can convince the relayer to accept. Repeated attacks drain the relayer's balance with no on-chain recourse.

### Likelihood Explanation

Any NEAR account can sign a `DelegateAction` and submit it to any public relayer. No special privilege is required. The attack is deterministic: Alice controls both the deposit amount and the receiver contract, so she can guarantee failure. The off-chain nature of the relayer agreement (analogous to the Connext off-chain router bid) means the relayer has already committed before it can detect the manipulation.

### Recommendation

The deposit refund for failed inner receipts in meta-transactions should be routed to the relayer (the `signer_id` of the outer action receipt), not to Alice (the `predecessor_id` of the inner receipt). The existing `ActionReceiptV2` / `refund_to` mechanism (`ReceiptEnum::ActionV2` with `refund_to: Option<AccountId>`) provides the infrastructure to override the refund destination. `apply_delegate_action` should set `refund_to = action_receipt.signer_id()` (the relayer) on the emitted inner receipt so that deposit refunds on failure return to the party who funded them.

### Proof of Concept

```
1. Alice deploys or identifies a contract on Bob's shard that always panics.
2. Alice signs:
     DelegateAction {
       sender_id: "alice.near",
       receiver_id: "always-panic.bob.near",
       actions: [FunctionCall { method: "panic", deposit: 100_000_000_000_000_000_000_000_000 /* 100 NEAR */ }],
       nonce: <valid>,
       max_block_height: <current + 100>,
       public_key: <alice's key>,
     }
3. Alice sends SignedDelegateAction to relayer off-chain.
4. Relayer submits outer tx (signer=relayer, receiver=alice.near).
5. apply_delegate_action emits inner receipt:
     predecessor_id = "alice.near"   ← Alice
     receiver_id    = "always-panic.bob.near"
     deposit        = 100 NEAR       ← paid by relayer
6. Inner receipt fails on Bob's shard.
7. refund_unspent_gas_and_deposits sends 100 NEAR to balance_refund_receiver()
   = predecessor_id = "alice.near".
8. Alice's balance: +100 NEAR. Relayer's balance: -100 NEAR.
```

### Citations

**File:** runtime/runtime/src/actions.rs (L455-469)
```rust
    // Generate a new receipt from DelegateAction.
    let new_receipt = Receipt::V0(ReceiptV0 {
        predecessor_id: sender_id.clone(),
        receiver_id: delegate_action.receiver_id().clone(),
        receipt_id: CryptoHash::default(),

        receipt: ReceiptEnum::Action(ActionReceipt {
            signer_id: action_receipt.signer_id().clone(),
            signer_public_key: action_receipt.signer_public_key().clone(),
            gas_price: action_receipt.gas_price(),
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: delegate_action.get_actions(),
        }),
    });
```

**File:** runtime/runtime/src/actions.rs (L471-475)
```rust
    // Note, Relayer prepaid all fees and all things required by actions: attached deposits and attached gas.
    // If something goes wrong, deposit is refunded to the predecessor, this is sender_id/Sender in DelegateAction.
    // Gas is refunded to the signer, this is Relayer.
    // Some contracts refund the deposit. Usually they refund the deposit to the predecessor and this is sender_id/Sender from DelegateAction.
    // Therefore Relayer should verify DelegateAction before submitting it because it spends the attached deposit.
```

**File:** runtime/runtime/src/lib.rs (L1169-1173)
```rust
                .ok_or(IntegerOverflowError)?;
        let deposit_refund = if result.result.is_err() { total_deposit } else { Balance::ZERO };
        let gross_gas_refund = if result.result.is_err() {
            prepaid_gas
                .checked_add(prepaid_exec_gas.gas)
```

**File:** runtime/runtime/src/lib.rs (L1269-1274)
```rust
        if deposit_refund > Balance::ZERO {
            result.new_receipts.push(Receipt::new_balance_refund(
                receipt.balance_refund_receiver(),
                deposit_refund,
            ));
        }
```

**File:** core/primitives/src/receipt.rs (L428-430)
```rust
    pub fn balance_refund_receiver(&self) -> &AccountId {
        self.refund_to().as_ref().unwrap_or_else(|| self.predecessor_id())
    }
```

**File:** docs/architecture/how/meta-tx.md (L236-242)
```markdown
The relayer can see what the cost will be before submitting the meta transaction
and agrees to pay for it, so nothing wrong so far. But what if the transaction
fails execution on Bob's shard? At this point, the predecessor is `Alice` and
therefore she receives the token balance refunded, not the relayer. This is
something relayer implementations must be aware of since there is a financial
incentive for Alice to submit meta transactions that have high balances attached
but will fail on Bob's shard.
```
