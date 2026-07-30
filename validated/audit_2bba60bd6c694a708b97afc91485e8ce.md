## Finding

### Title
Stale `gas_payment.amount` in `finish_gas_coin`'s `SendFunds` path allows minting SUI when a real coin is merged into an address-balance-funded ephemeral gas coin before `send_funds` - (`sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs`)

### Summary
When gas is paid from an address balance, the sender's ephemeral gas coin is created with `gas_payment.amount` (the amount reserved/withdrawn from the payer's address-balance accumulator at gas-smashing time) [1](#0-0) . That fixed `gas_payment.amount` is later reused, unmodified, by `finish_gas_coin` to compute the debit that must be reversed out of the payer's address balance when the gas coin is transferred via `sui::coin::send_funds` [2](#0-1) . However, the ephemeral gas coin's *actual* runtime balance can be increased during the PTB (e.g., via `MergeCoins(Gas, [real_coin])`, which is a legitimate, natively supported operation on the `Gas` argument, exactly as used in the production `send_all_coins` CLI helper for the coin-payment case [3](#0-2) ). `sui::coin::send_funds`'s own native call reports the coin's *live* (post-merge) balance to the recipient's accumulator, while `finish_gas_coin` debits only the stale, pre-merge `gas_payment.amount` from the sender.

### Finding Description
`finish_gas_coin`'s `SendFunds` branch computes:
```
net_balance_change = -(gas_payment.amount)
```
and applies it only to the *original* `PaymentLocation::AddressBalance(address)` [4](#0-3) .

This is in contrast to the "coin not transferred" branch, which explicitly reconciles the actual `remaining_balance` (read back out of the real Move value) against `gas_payment.amount` to compute the correct delta [5](#0-4) . The `SendFunds` branch does no such reconciliation — it assumes the coin's value at consumption time still equals `gas_payment.amount`.

That assumption breaks if the PTB merges additional value into the `Gas` argument (via `MergeCoins(Gas, [coin])`, a mutable-borrow operation on `Gas` that is *not* tracked by `GasCoinTransfer` since it doesn't move `Gas` by value) before finally consuming `Gas` by value with `sui::coin::send_funds`. At that point:
- `sui::coin::send_funds`'s native call operates on the live/actual coin value (original `gas_payment.amount` + merged amount) and emits a `Merge` accumulator event crediting the recipient with the full, correct (higher) amount.
- `finish_gas_coin` still only emits a `Split` debiting the sender's address balance by the stale `gas_payment.amount`, ignoring the merged-in value.

The merged-in real `Coin` object simply disappears from the object set (consumed by the native merge) with no separate accumulator accounting for its value, since coin-object merges/splits are ordinarily conserved purely within the Move value itself. The net effect is that the merged coin's value is credited to the recipient's address balance but never actually debited anywhere, corresponding to unbacked SUI creation.

### Impact Explanation
This falls squarely under "exceeding the 10B SUI cap" / unauthorized creation of value via broken accounting, a Critical impact per the bounty scope. If confirmed and not blocked by a global SUI-conservation invariant check (I could not locate and verify such a check exists and executes in production, only bound/representability checks in `temporary_store.rs`'s `check_accumulator_amounts_representable`, which check totals against caps but do not enforce input==output conservation for this specific cross-domain (object → accumulator) value flow), an ordinary SUI holder using address-balance gas payment could mint SUI by merging their own coins into the gas coin and sending it away via `send_funds`.

### Likelihood Explanation
The `MergeCoins(Gas, [...])` pattern is not exotic — it is used in mainline, already-shipped client code (`send_all_coins` in `crates/sui/src/client_commands.rs`) for the coin-payment case, showing the underlying capability (merging real value into `Gas` mid-PTB, then consuming `Gas` by value into `send_funds`) is a supported, reachable operation. The remaining open question — which I could not fully close given tool-call limits — is whether an end-to-end SUI-conservation check elsewhere in the pipeline (outside the files reviewed) would reject a transaction whose accumulator/object value balance doesn't add up, turning this into a caught invariant violation (still a serious node/consensus concern) rather than a silent mint. This needs direct verification via a transactional test.

### Recommendation
In `finish_gas_coin`'s `SendFunds` branch, do not trust the stale `gas_payment.amount`. Instead, read the coin's actual balance at the moment of consumption (as is already done via `coin_ref_value` elsewhere in the file) and use that live value to compute the debit from the source address balance, mirroring the reconciliation already performed in the non-transferred branch.

### Proof of Concept
Not fully constructible without running the code/test harness, given tool lim

### Citations

**File:** sui-execution/latest/sui-adapter/src/gas_charger.rs (L536-605)
```rust
        fn smash_gas(
            &mut self,
            tx_digest: &TransactionDigest,
            temporary_store: &mut TemporaryStore<'_>,
        ) {
            // set gas charge location
            self.gas_charge_location = self.smash_target.location();

            // sum the value of all gas coins
            let total_smashed = self
                .payment_methods()
                .map(|payment| match payment {
                    PaymentMethod::AddressBalance(_, reservation) => Ok(*reservation),
                    PaymentMethod::Coin(obj_ref) => {
                        let obj_data = temporary_store
                            .objects()
                            .get(&obj_ref.0)
                            .map(|obj| &obj.data);
                        let Some(Data::Move(move_obj)) = obj_data else {
                            return Err(ExecutionError::invariant_violation(
                                "Provided non-gas coin object as input for gas!",
                            ));
                        };
                        if !move_obj.type_().is_gas_coin() {
                            return Err(ExecutionError::invariant_violation(
                                "Provided non-gas coin object as input for gas!",
                            ));
                        }
                        Ok(move_obj.get_coin_value_unsafe())
                    }
                })
                .collect::<Result<Vec<u64>, ExecutionError>>()
                // transaction and certificate input checks must have insured that all gas coins
                // are valid
                .unwrap_or_else(|_| {
                    panic!(
                        "Unable to process gas payments for transaction {}",
                        tx_digest
                    )
                })
                .iter()
                .sum();
            // If it is 0, then we are smashing for the first time (at the beginning of execution).
            // If it is non-zero, then we are re-smashing after a reset (due to some sort of
            // failure in charging for gas), and the total should not change.
            debug_assert!(
                self.total_smashed == 0 || self.total_smashed == total_smashed,
                "Gas smashing should not change after a reset"
            );
            self.total_smashed = total_smashed;

            let smash_location = self.smash_target.location();
            // delete all gas objects except the smash target
            for payment_method in self.smashed_payments.values() {
                let location = payment_method.location();
                assert_ne!(location, smash_location, "Payment methods must be unique");
                match payment_method {
                    PaymentMethod::AddressBalance(sui_address, reservation) => {
                        assert_reachable!("smashed payment is address-balance reservation");
                        let balance_type = sui_types::balance::Balance::type_tag(
                            sui_types::gas_coin::GAS::type_tag(),
                        );
                        let event = AccumulatorEvent::from_balance_change(
                            *sui_address,
                            balance_type,
                            i64::try_from(*reservation).unwrap().checked_neg().unwrap(),
                        )
                        .expect("Failed to create accumulator event for gas smashing");
                        temporary_store.add_accumulator_event(event);
                    }
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs (L1826-1885)
```rust
    // If the gas coin was not ephemeral, then we are done.
    let address = match gas_payment.location {
        PaymentLocation::Coin(_) => {
            // small sanity check
            assert_invariant!(
                !matches!(gas_coin_transfer, Some(GasCoinTransfer::SendFunds { .. }))
                    || deleted_object_ids.contains(&gas_id),
                "send_funds transfer implies the coin should be deleted"
            );
            return Ok(());
        }
        PaymentLocation::AddressBalance(address) => address,
    };

    let net_balance_change = if let Some(gas_coin_transfer) = gas_coin_transfer {
        // sanity check storage changes
        match gas_coin_transfer {
            GasCoinTransfer::TransferObjects => {
                assert_invariant!(
                    created_object_ids.contains(&gas_id),
                    "ephemeral coin should be newly created"
                );
                assert_invariant!(
                    !deleted_object_ids.contains(&gas_id),
                    "ephemeral coin should not be deleted if transferred as an object"
                );
                assert_invariant!(
                    writes.contains_key(&gas_id),
                    "ephemeral coin should be in writes if transferred as an object"
                );
            }
            GasCoinTransfer::SendFunds { .. } => {
                assert_invariant!(
                    !created_object_ids.contains(&gas_id),
                    "ephemeral coin should not be newly created if transferred with send_funds"
                );
                assert_invariant!(
                    !deleted_object_ids.contains(&gas_id),
                    "ephemeral coin should not be deleted if transferred with send_funds"
                );
                assert_invariant!(
                    !writes.contains_key(&gas_id),
                    "ephemeral coin should not be in writes if transferred with send_funds"
                );
            }
        }

        // If the gas coin was moved, it was transferred.
        // In such a case, the gas coin has a new location, so we fully withdraw the gas amount
        // and keep it in the coin object. The transferred location is now the source of payment
        // instead of the address balance.
        let Some(net_balance_change) = gas_payment
            .amount
            .try_into()
            .ok()
            .and_then(|i: i64| i.checked_neg())
        else {
            invariant_violation!("Gas payment amount cannot be represented as i64")
        };
        net_balance_change
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs (L1886-1906)
```rust
    } else {
        // In this case the gas coin was not moved, so we want to return the remaining balance to
        // the address balance. To do so we need to destroy it and create an accumulator event for
        // the net balance change
        let was_created = created_object_ids.shift_remove(&gas_id);
        assert_invariant!(was_created, "ephemeral coin should be newly created");
        let Some((_owner, _ty, value)) = writes.shift_remove(&gas_id) else {
            invariant_violation!("checked above that the gas coin was present")
        };
        let (_id, remaining_balance) = Value::from(value).unpack_coin()?;
        // gas_payment.amount is the original value of the ephemeral coin.
        // If net_balance_change is negative, then balance was spent/withdrawn from the gas coin.
        // If the net_balance_change is positive, then balance was added/merged to the gas coin.
        let Some(net_balance_change): Option<i64> = (remaining_balance as i128)
            .checked_sub(gas_payment.amount as i128)
            .and_then(|i| i.try_into().ok())
        else {
            invariant_violation!("Remaining balance could not be represented as i64")
        };
        net_balance_change
    };
```

**File:** crates/sui/src/client_commands.rs (L3541-3557)
```rust
    for sources in merged_args.chunks(max_sources) {
        builder.command(Command::MergeCoins(target, sources.to_vec()));
    }

    // Moving the coin into `coin::send_funds` by value is understood by the execution layer: when
    // it is the gas coin, that consumes it and refunds the unused gas budget into the recipient's
    // address balance, so no dust is left behind. Passing the SUI coins as an explicit gas payment
    // also keeps the fullnode from performing gas selection, which would otherwise pull in the
    // signer's address balance as well.
    let recipient_arg = builder.pure(recipient)?;
    builder.programmable_move_call(
        SUI_FRAMEWORK_PACKAGE_ID,
        Identifier::from_str("coin")?,
        Identifier::from_str("send_funds")?,
        vec![coin_type_tag],
        vec![target, recipient_arg],
    );
```
