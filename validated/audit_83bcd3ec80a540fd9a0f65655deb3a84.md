No vulnerability found for this question.

## Analysis

The premise doesn't hold up structurally in this codebase.

**Both `secondary_signers()` and `is_multi_agent()` derive from the same single source — the `TransactionAuthenticator`.** There is no separate "RawTransaction variant" that independently encodes multi-agent status. `RawTransaction` itself has no multi-agent signaling field; multi-agent status lives exclusively in the `TransactionAuthenticator` enum's `MultiAgent`/`FeePayer` variants, which carry `secondary_signer_addresses`/`secondary_signers`.

In `TransactionMetadata::new`, both fields are populated from the exact same authenticator object in the same call: [1](#0-0) 

`is_multi_agent()` is computed directly from those same fields, not from a separately-parsed variant: [2](#0-1) 

Because `secondary_signers` and the boolean used by `is_multi_agent` are literally the same underlying data (not independently parsed from two different structures), there's no way to construct an authenticator/raw-transaction pair that makes them disagree.

Additionally, the dispatch order in `transaction_validation.rs` closes the one theoretically ambiguous case (fee-payer present with empty secondary signers, which does make `is_multi_agent()` true via the `fee_payer.is_some()` clause): the fee-payer branch is checked **before** the multi-agent branch, so that case is routed to `fee_payer_prologue_extended`/`fee_payer_script_prologue`, never to `multi_agent_prologue_extended`: [3](#0-2) 

Consequently, `multi_agent_prologue_extended` is only reached when `fee_payer` is `None` **and** `is_multi_agent()` is true, which (given `fee_payer.is_none()`) mathematically requires `secondary_signers` to be non-empty. There is no code path where `multi_agent_prologue_extended` is dispatched with zero secondary signers.

The separate `SignedTransaction::is_multi_agent()` in `types/src/transaction/mod.rs` (which pattern-matches on `TransactionAuthenticator::MultiAgent`) is a distinct, unrelated helper not used in the prologue-dispatch decision in `transaction_validation.rs` — the dispatch uses `TransactionMetadata::is_multi_agent()` exclusively, so there's no cross-type inconsistency being exploited either. [4](#0-3) 

No admission-boundary invariant is broken; the finding as described is not reproducible against this code.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L134-142)
```rust
            secondary_signers: txn.authenticator().secondary_signer_addresses(),
            secondary_authentication_proofs: txn
                .authenticator()
                .secondary_signers()
                .iter()
                .map(|account_auth| account_auth.authentication_proof())
                .collect(),
            replay_protector: txn.replay_protector(),
            fee_payer: txn.authenticator_ref().fee_payer_address(),
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L287-289)
```rust
    pub fn is_multi_agent(&self) -> bool {
        !self.secondary_signers.is_empty() || self.fee_payer.is_some()
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

**File:** types/src/transaction/mod.rs (L1579-1584)
```rust
    pub fn is_multi_agent(&self) -> bool {
        matches!(
            self.authenticator,
            TransactionAuthenticator::MultiAgent { .. }
        )
    }
```
