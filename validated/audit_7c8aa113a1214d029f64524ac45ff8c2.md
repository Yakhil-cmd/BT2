Based on the code I could inspect, I found a genuine bug in the **legacy (non-versioned) prologue/epilogue selection logic**, but I was unable to confirm whether the same flaw exists in the **default, versioned prologue path** (`transaction_validation_versioned.rs`), since `VERSIONED_TRANSACTION_VALIDATION` is itself a default-enabled feature that reroutes `run_script_prologue`/`run_epilogue` away from the code shown below [1](#0-0) , and I ran out of iterations before I could read that file. I also could not verify, from `types/src/transaction/authenticator.rs`, the exact wire-level semantics that let `fee_payer_address()` return `Some` while `fee_payer_signer()`/`fee_payer_authentication_proof` returns `None` for a signature that still passes verification — the doc comment on `TransactionMetadata::fee_payer_authentication_proof` strongly implies this is an intentional, reachable state [2](#0-1) , but I did not confirm the exact conditions under which the `TransactionAuthenticator` allows it.

### Title
Prologue/epilogue gas-payer binding mismatch when fee-payer address is set without a fee-payer authentication proof - (File: aptos-move/aptos-vm/src/transaction_validation.rs)

### Summary
In the legacy (non-versioned, non-account-abstraction) prologue path, whether `fee_payer_script_prologue` is invoked depends on **both** `fee_payer` and `fee_payer_authentication_proof` being `Some` [3](#0-2) . If the auth proof is missing while the address is still set, the code silently falls into the `multi_agent_script_prologue` branch instead, because `is_multi_agent()` only checks `fee_payer.is_some()` [4](#0-3) . However, the corresponding epilogue selection only checks `txn_data.fee_payer()` (address presence), independent of whether an auth proof existed [5](#0-4) , so gas is still debited from the `fee_payer` address via `epilogue_gas_payer`, using that address directly (`MoveValue::Address(fee_payer)`, not a validated `Signer`) [6](#0-5) .

This means: the prologue that is actually executed (`multi_agent_script_prologue`) performs no balance/authentication check tied to the `fee_payer` address at all, yet the epilogue unconditionally treats that same address as the gas payer to debit.

### Finding Description
`Features::FEE_PAYER_ACCOUNT_OPTIONAL` (flag 35, on by default) [7](#0-6) [8](#0-7)  is only referenced in the feature registry/release-builder files; there is no `Features::is_fee_payer_account_optional_enabled()` accessor and no gating call site in `aptos-vm` — the flag is defined but never consulted by `transaction_validation.rs`, `transaction_metadata.rs`, or `aptos_vm.rs`. This means the "optional fee payer" wire-state (`fee_payer: Some(addr)`, `fee_payer_authentication_proof: None`) is handled purely by the fallback logic in the branch conditions shown above, not by an explicit feature check, so any code path reachable through the authenticator can trigger it regardless of the flag's value.

`TransactionMetadata::new` explicitly documents that `fee_payer_authentication_proof` can be `None` "if the `TransactionAuthenticator` lacks an authenticator for the fee payer" [2](#0-1) , while `fee_payer` (the address) comes from a separate accessor, `txn.authenticator_ref().fee_payer_address()` [9](#0-8) . If these two are independently populated by the wire authenticator, a transaction can present a `fee_payer` address without any corresponding authentication for it.

Given that state, in `run_script_prologue`'s legacy branch, the `if let (Some(fee_payer), Some(fee_payer_auth_key))` guard fails and the transaction is routed to `multi_agent_script_prologue` instead of `fee_payer_script_prologue` [10](#0-9) . The multi-agent prologue Move function is not designed to validate or reserve gas from a "fee payer" — it only knows about sender + secondary signers. Yet `run_epilogue` still finds `txn_data.fee_payer()` to be `Some` and unconditionally calls `epilogue_gas_payer`/`epilogue_gas_payer_extended`, passing the fee-payer address directly to debit gas from it [11](#0-10) .

### Impact Explanation
If reachable, this breaks the invariant that "the gas payer identity used for balance debit must match the signer that actually authenticated," exactly as the review question states — the prologue never validates that the fee-payer account exists, has sufficient balance, or authenticated at all (since it takes the multi-agent path instead), while the epilogue still attempts to debit gas from that unverified address. Depending on what `epilogue_gas_payer`'s Move implementation actually checks internally (which I did not fully trace into the Move framework source), this could range from a benign abort (if the Move function re-derives/rechecks the fee payer independently) to genuine fee-payer confusion/gas-griefing against an arbitrary address supplied by an unprivileged attacker.

### Likelihood Explanation
**Uncertain / not fully confirmed.** Two open questions prevent a high-confidence verdict:
1. Whether `VERSIONED_TRANSACTION_VALIDATION` (a default-enabled feature) reroutes execution to `transaction_validation_versioned::run_prologue`/`run_epilogue` before reaching the mismatched branches above [1](#0-0)  — I did not get to review that file's branch logic to see if it has the same address/proof mismatch or handles it correctly.
2. Whether the `TransactionAuthenticator` parsing/signature-verification layer in `types/src/transaction/authenticator.rs` actually permits a syntactically/cryptographically valid transaction where `fee_payer_address()` is `Some` but `fee_payer_signer()` is `None` for an unprivileged, self-crafted transaction (as opposed to only being reachable via account-abstraction/dispatchable-authentication flows that are separately validated elsewhere).

### Recommendation
- Confirm in `transaction_validation_versioned.rs` whether the default execution path has an equivalent mismatch, and if so, align the prologue/epilogue selection logic (e.g., make `is_multi_agent()`/prologue routing and the epilogue's fee-payer check use the identical condition — including auth-proof presence).
- Confirm in `authenticator.rs` under what exact wire/verification conditions `fee_payer_address()` can be non-`None` while the fee payer’s own authenticator/proof is absent, and ensure that in that case the prologue path used matches the one the epilogue assumes.
- Add a Rust unit test constructing a `SignedTransaction` with `fee_payer` set and no fee-payer authenticator entry, and assert either a rejection or a wired-through, verified debit path rather than a silent mismatch.

### Proof of Concept
Conceptual, not fully verified end-to-end due to the two open questions above:
1. Construct a multi-agent/fee-payer `SignedTransaction` where the `TransactionAuthenticator`'s fee-payer slot is omitted/`NoAccountAuthenticator` but the `fee_payer` address field is still populated.
2. Submit via mempool/VM validator; if it reaches `AptosVM::run_script_prologue` on the legacy path, verify it is routed to `multi_agent_script_prologue` instead of `fee_payer_script_prologue`.
3. Verify the corresponding epilogue call still targets the unauthenticated `fee_payer` address for gas debit via `epilogue_gas_payer`.

**Given the unresolved uncertainty about the default (versioned) path and authenticator-level admissibility, I cannot certify this as a confirmed, end-to-end exploitable admission-boundary bug from the evidence gathered — it should be treated as a flagged area requiring deeper investigation into `transaction_validation_versioned.rs` and `authenticator.rs` before final classification.**

### Citations

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L125-135)
```rust
    if features.is_versioned_transaction_validation_enabled() {
        return crate::transaction_validation_versioned::run_prologue(
            session,
            module_storage,
            serialized_signers,
            txn_data,
            log_context,
            traversal_context,
            is_simulation,
        );
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L288-330)
```rust
        let (prologue_function_name, args) = if let (Some(fee_payer), Some(fee_payer_auth_key)) = (
            txn_data.fee_payer(),
            txn_data
                .fee_payer_authentication_proof
                .as_ref()
                .map(|proof| proof.optional_auth_key()),
        ) {
            if features.is_transaction_simulation_enhancement_enabled() {
                let args = vec![
                    MoveValue::Signer(txn_data.sender),
                    MoveValue::U64(txn_sequence_number),
                    MoveValue::vector_u8(txn_authentication_key.unwrap_or_default()),
                    MoveValue::vector_address(txn_data.secondary_signers()),
                    MoveValue::Vector(secondary_auth_keys),
                    MoveValue::Address(fee_payer),
                    MoveValue::vector_u8(fee_payer_auth_key.unwrap_or_default()),
                    MoveValue::U64(txn_gas_price.into()),
                    MoveValue::U64(txn_max_gas_units.into()),
                    MoveValue::U64(txn_expiration_timestamp_secs),
                    MoveValue::U8(chain_id.id()),
                    MoveValue::Bool(is_simulation),
                ];
                (
                    &APTOS_TRANSACTION_VALIDATION.fee_payer_prologue_extended_name,
                    args,
                )
            } else {
                let args = vec![
                    MoveValue::Signer(txn_data.sender),
                    MoveValue::U64(txn_sequence_number),
                    MoveValue::vector_u8(txn_authentication_key.unwrap_or_default()),
                    MoveValue::vector_address(txn_data.secondary_signers()),
                    MoveValue::Vector(secondary_auth_keys),
                    MoveValue::Address(fee_payer),
                    MoveValue::vector_u8(fee_payer_auth_key.unwrap_or_default()),
                    MoveValue::U64(txn_gas_price.into()),
                    MoveValue::U64(txn_max_gas_units.into()),
                    MoveValue::U64(txn_expiration_timestamp_secs),
                    MoveValue::U8(chain_id.id()),
                ];
                (&APTOS_TRANSACTION_VALIDATION.fee_payer_prologue_name, args)
            }
        } else if txn_data.is_multi_agent() {
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L552-593)
```rust
        // We can unconditionally do this as this condition can only be true if the prologue
        // accepted it, in which case the gas payer feature is enabled.
        if let Some(fee_payer) = txn_data.fee_payer() {
            let (func_name, args) = {
                if features.is_transaction_simulation_enhancement_enabled() {
                    let args = vec![
                        MoveValue::Signer(txn_data.sender),
                        MoveValue::Address(fee_payer),
                        MoveValue::U64(fee_statement.storage_fee_refund()),
                        MoveValue::U64(txn_gas_price.into()),
                        MoveValue::U64(txn_max_gas_units.into()),
                        MoveValue::U64(gas_remaining.into()),
                        MoveValue::Bool(is_simulation),
                    ];
                    (
                        &APTOS_TRANSACTION_VALIDATION.user_epilogue_gas_payer_extended_name,
                        args,
                    )
                } else {
                    let args = vec![
                        MoveValue::Signer(txn_data.sender),
                        MoveValue::Address(fee_payer),
                        MoveValue::U64(fee_statement.storage_fee_refund()),
                        MoveValue::U64(txn_gas_price.into()),
                        MoveValue::U64(txn_max_gas_units.into()),
                        MoveValue::U64(gas_remaining.into()),
                    ];
                    (
                        &APTOS_TRANSACTION_VALIDATION.user_epilogue_gas_payer_name,
                        args,
                    )
                }
            };
            session.execute_function_bypass_visibility(
                &APTOS_TRANSACTION_VALIDATION.module_id(),
                func_name,
                vec![],
                serialize_values(&args),
                &mut UnmeteredGasMeter,
                traversal_context,
                module_storage,
            )
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L27-30)
```rust
    pub fee_payer: Option<AccountAddress>,
    /// `None` if the [TransactionAuthenticator] lacks an authenticator for the fee payer.
    /// `Some([])` if the authenticator for the fee payer is a [NoAccountAuthenticator].
    pub fee_payer_authentication_proof: Option<AuthenticationProof>,
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L142-146)
```rust
            fee_payer: txn.authenticator_ref().fee_payer_address(),
            fee_payer_authentication_proof: txn
                .authenticator()
                .fee_payer_signer()
                .map(|signer| signer.authentication_proof()),
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L287-289)
```rust
    pub fn is_multi_agent(&self) -> bool {
        !self.secondary_signers.is_empty() || self.fee_payer.is_some()
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L55-55)
```rust
    FEE_PAYER_ACCOUNT_OPTIONAL = 35,
```

**File:** types/src/on_chain_config/aptos_features.rs (L269-269)
```rust
            Self::FEE_PAYER_ACCOUNT_OPTIONAL,
```
