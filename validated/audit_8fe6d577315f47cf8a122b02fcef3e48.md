### Title
Multisig transaction payload substitution when `abort_if_multisig_payload_mismatch` feature is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`validate_multisig_transaction`, the Move function invoked by the VM prologue for every multisig-account transaction, only compares the payload supplied at execution time against the on-chain approved payload when a specific feature flag is enabled. When that flag is off, an owner with enough approvals to execute a pending multisig transaction can substitute an entirely different `EntryFunction` payload than the one the other owners actually voted on, and it will pass admission and execute under the multisig account's authority.

### Finding Description
The VM prologue calls `run_multisig_prologue` [1](#0-0)  which builds `provided_payload` from whatever `TransactionExecutableRef` is attached to the *currently submitted* transaction (not necessarily the one the owners approved), and passes it into the Move-level `validate_multisig_transaction` function [2](#0-1) .

Inside `validate_multisig_transaction`:
- If the multisig transaction was created with only a payload hash (`create_transaction_with_hash`), the supplied payload's hash is checked against `transaction.payload_hash` — this path is sound.
- If the multisig transaction was created with the *full payload stored on-chain* (`create_transaction`), then `transaction.payload` is `Some(..)`, but the comparison between the stored `transaction.payload` and the newly supplied `payload` is only performed when `features::abort_if_multisig_payload_mismatch_enabled()` is `true`: [3](#0-2) 

When that feature is disabled, the function proceeds to execute the transaction using whatever payload is on-chain (via `MultisigAccount` at execution time) without ever verifying that the payload supplied by the executing owner matches what the quorum of owners approved. Since owner approvals (`approve_transaction`) are recorded against the transaction's `sequence_number`, not against the exact entry-function bytes actually executed, this creates a divergence between "what was approved" and "what is executed" — an approval-set/payload binding failure at the transaction admission boundary.

### Impact Explanation
This breaks the core multisig invariant that execution requires k-of-n approval *of a specific payload*. With the mismatch-check feature disabled, a single owner (as long as they can reach quorum count, e.g., they are one of the last approvers or can otherwise trigger execution) can execute an arbitrary payload of their choosing on behalf of the multisig account, bypassing the intent of the other approving owners. This is a wrong-approval-set admission failure with High/Critical impact, since it allows execution of an unauthorized entry function under the multisig account's signer authority (fund transfers, ownership changes, etc.), fitting the "authenticator/multisig approval validation accepting the wrong approval set" category from the Admission Impact Gate.

### Likelihood Explanation
Likelihood is directly gated by whether `abort_if_multisig_payload_mismatch_enabled` feature flag is turned on in the deployed configuration. I was unable to determine conclusively, within the available tooling, whether this flag is enabled by default in genesis/mainnet configuration for this repository snapshot — the flag and its accessor are defined in `features.move`/`features.spec.move`, but I could not fetch the exact default-enablement list (`aptos-move/aptos-release-builder/src/components/feature_flags.rs` and `types/src/on_chain_config/aptos_features.rs` reference it, but their content wasn't retrievable via the available search in the remaining iterations). If the flag defaults to disabled (which the guarded, opt-in style of the code and its being introduced as a "fix" suggests), the exposure window applies to any network/testnet that hasn't enabled it, and to any multisig transaction created via `create_transaction` (full payload stored) as opposed to `create_transaction_with_hash`.

### Recommendation
- Make the payload-match check unconditional (not gated by a feature flag) whenever `transaction.payload` is `Some(..)`, regardless of whether the supplied `payload` argument is non-empty, so any submitted payload is always verified equal to what is stored on-chain.
- Alternatively, if VM callers can legitimately omit the payload at execution time (relying on the stored payload), ensure the codepath uses the *stored* payload for execution deterministically rather than accepting an owner-supplied alternative silently.
- Confirm the feature flag's on-chain default and prioritize enabling `abort_if_multisig_payload_mismatch_enabled` network-wide, or remove the flag gate entirely and make the check the default protected behavior.

### Proof of Concept
1. Owner A calls `multisig_account::create_transaction(owner_a, multisig_addr, payload_A_bytes)` where `payload_A` is `MultisigTransactionPayload::EntryFunction(transfer_small_amount)`. This stores the full payload on-chain (`transaction.payload = Some(payload_A)`, `transaction.payload_hash = None`).
2. Owners B and C review `payload_A` off-chain (e.g., via a UI showing the stored payload) and call `approve_transaction` for that sequence number, believing they are approving `payload_A`.
3. Assume `features::abort_if_multisig_payload_mismatch_enabled()` is disabled (default/dev/test network state).
4. Owner A (or any owner reaching quorum) submits the actual execution transaction, but this time supplies `TransactionExecutableRef::EntryFunction(payload_B)` where `payload_B` is `MultisigTransactionPayload::EntryFunction(transfer_full_balance_to_attacker)`.
5. In `run_multisig_prologue`, `provided_payload = bcs::to_bytes(MultisigTransactionPayload::EntryFunction(payload_B))`. In `validate_multisig_transaction`: `transaction.payload_hash.is_some()` is `false` (no hash was ever committed), so that check is skipped; the second check (`abort_if_multisig_payload_mismatch_enabled && transaction.payload.is_some() && !payload.is_empty()`) evaluates to `false` because the feature is disabled — so no comparison between `payload_A` and `payload_B` occurs.
6. The transaction is admitted and `payload_B` (the attacker's substituted entry function) executes under the multisig account's signer authority, despite owners B and C having approved `payload_A` only. [4](#0-3)

### Citations

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L419-460)
```rust
pub(crate) fn run_multisig_prologue(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl ModuleStorage,
    txn_data: &TransactionMetadata,
    executable: TransactionExecutableRef,
    multisig_address: AccountAddress,
    features: &Features,
    log_context: &AdapterLogSchema,
    traversal_context: &mut TraversalContext,
) -> Result<(), VMStatus> {
    let unreachable_error = VMStatus::error(StatusCode::UNREACHABLE, None);
    // Note[Orderless]: Earlier the `provided_payload` was being calculated as bcs::to_bytes(MultisigTransactionPayload::EntryFunction(entry_function)).
    // So, converting the executable to this format.
    let provided_payload = match executable {
        TransactionExecutableRef::EntryFunction(entry_function) => bcs::to_bytes(
            &MultisigTransactionPayload::EntryFunction(entry_function.clone()),
        )
        .map_err(|_| unreachable_error.clone())?,
        TransactionExecutableRef::Empty => {
            if features.is_abort_if_multisig_payload_mismatch_enabled() {
                vec![]
            } else {
                bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| unreachable_error.clone())?
            }
        },
        TransactionExecutableRef::Script(script) => {
            if !features.is_multisig_script_enabled() {
                return Err(VMStatus::error(
                    StatusCode::FEATURE_UNDER_GATING,
                    Some("Multisig script payload is not enabled".to_string()),
                ));
            }
            bcs::to_bytes(&MultisigTransactionPayload::Script(script.clone()))
                .map_err(|_| unreachable_error.clone())?
        },
        TransactionExecutableRef::Encrypted => {
            return Err(VMStatus::error(
                StatusCode::FEATURE_UNDER_GATING,
                Some("Encrypted payload not supported for multisig transactions".to_string()),
            ));
        },
    };
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L462-479)
```rust
    session
        .execute_function_bypass_visibility(
            &MULTISIG_ACCOUNT_MODULE,
            VALIDATE_MULTISIG_TRANSACTION,
            vec![],
            serialize_values(&vec![
                MoveValue::Signer(txn_data.sender),
                MoveValue::Address(multisig_address),
                MoveValue::vector_u8(provided_payload),
            ]),
            &mut UnmeteredGasMeter,
            traversal_context,
            module_storage,
        )
        .map(|_return_vals| ())
        .map_err(expect_no_verification_errors)
        .or_else(|err| convert_prologue_error(err, log_context))
}
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1382)
```text
    fun validate_multisig_transaction(
        owner: &signer, multisig_account: address, payload: vector<u8>) {
        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        assert_transaction_exists(multisig_account, sequence_number);

        if (features::multisig_v2_enhancement_feature_enabled()) {
            assert!(
                can_execute(address_of(owner), multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        }
        else {
            assert!(
                can_be_executed(multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        };

        // Count approvals, including the executing owner's implicit vote.
        let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
        if (!has_voted_for_approval(multisig_account, sequence_number, address_of(owner))) {
            num_approvals += 1;
        };
        assert!(num_approvals >= num_signatures_required(multisig_account), error::invalid_argument(ENOT_ENOUGH_APPROVALS));

        // Timelock check — separate from quorum so the error is unambiguous.
        assert!(
            can_execute_with_timelock(multisig_account, sequence_number, num_approvals),
            error::invalid_state(ETIMELOCK_NOT_EXPIRED),
        );

        // If the transaction payload is not stored on chain, verify that the provided payload matches the hashes stored
        // on chain.
        let multisig_account_resource = borrow_global<MultisigAccount>(multisig_account);
        let transaction = multisig_account_resource.transactions.borrow(sequence_number);
        if (transaction.payload_hash.is_some()) {
            let payload_hash = transaction.payload_hash.borrow();
            assert!(
                sha3_256(payload) == *payload_hash,
                error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH_HASH),
            );
        };

        // If the transaction payload is stored on chain and there is a provided payload,
        // verify that the provided payload matches the stored payload.
        if (features::abort_if_multisig_payload_mismatch_enabled()
            && transaction.payload.is_some()
            && !payload.is_empty()
        ) {
            let stored_payload = transaction.payload.borrow();
            assert!(
                payload == *stored_payload,
                error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH),
```
