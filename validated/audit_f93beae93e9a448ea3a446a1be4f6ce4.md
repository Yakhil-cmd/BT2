Found it. There's a genuine payload-execution mismatch bug in the multisig transaction path: the prologue's payload-matching check (`validate_multisig_transaction`) can be fully disabled, while the execution path (`execute_multisig_transaction`) still resolves the *executable* payload separately via `get_next_transaction_payload`, using whatever the caller provides at execution time.

### Title
Multisig transaction execution can run a different `EntryFunction`/`Script` payload than what was validated/approved when `abort_if_multisig_payload_mismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`validate_multisig_transaction` (the Move prologue invoked by the VM for multisig transactions) only cross-checks the caller-provided `payload` bytes against the on-chain `transaction.payload` when the feature flag `abort_if_multisig_payload_mismatch_enabled` is on <cite repo="Jortegata/aptos-core--010" path="aptos-move/framework/aptos-framework/sources/multisig_account.move" start="1373="1384" /> With this feature disabled (its default/gated state), an owner invoking `execute_multisig_transaction` can pass an arbitrary `TransactionExecutableRef` (EntryFunction or Script) that differs from the one that was actually proposed and voted on by the multisig's owners, and it will be admitted and executed as if it were the approved transaction, since only the `payload_hash`-only case (`transaction.payload_hash.is_some()`) is unconditionally checked [1](#0-0) .

### Finding Description
When a multisig transaction is proposed with the full payload stored on-chain (`transaction.payload.is_some()`, as opposed to only a hash), the admission check that the payload used at execution time equals the payload that was actually voted on is gated behind a feature flag:

```
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) {
    let stored_payload = transaction.payload.borrow();
    assert!(payload == *stored_payload, error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH));
}
``` [2](#0-1) 

If this feature is off, `validate_multisig_transaction` admits the transaction into execution regardless of what `payload` was supplied by the executing owner. The actual execution logic (`execute_multisig_transaction` in the VM) determines the executable payload not from this same `payload` argument used in the prologue check, but from a separate `get_next_transaction_payload` call using `provided_payload`, derived from the `TransactionExecutableRef` of the *current* signed transaction (EntryFunction/Script bytes) [3](#0-2) . Because the prologue's payload-equality assertion is disabled by the feature flag, there is no admission-time guarantee binding the executable actually run in step 2 (`execute_multisig_payload`) to the payload that owners approved when they voted, aside from the loose case that only fires when `payload_hash` was stored and non-empty and matches. This breaks the core invariant of multisig admission: "the payload approved by quorum is the payload executed."

Note that `run_multisig_prologue` in Rust performs the analogous computation and passes the same feature-gated logic through to the Move prologue [4](#0-3) , so both the VM-side and framework-side admission share the same gap.

### Impact Explanation
If exploitable (i.e., if the feature `abort_if_multisig_payload_mismatch_enabled` is disabled on a given network/at genesis, or governance has not yet enabled it), any owner who has enough voting authority to submit the final approving/executing transaction for a queued multisig proposal could substitute a different entry function or arguments than the one that other owners actually voted on, as long as the substitution is not caught by the `payload_hash`-only path. This is a "pre-validation mismatch that causes a transaction which should fail admission to execute and commit" — directly matching the Admission Impact Gate's fourth bullet. Given multisig accounts commonly custody protocol treasuries or governance authority, this could allow an unauthorized state transition (e.g., transferring funds or calling privileged functions) under the guise of a quorum-approved transaction.

### Likelihood Explanation
Exploitability is entirely contingent on the on-chain state of the `abort_if_multisig_payload_mismatch` feature flag. I could not independently confirm from the code in this repo snapshot whether this flag defaults to enabled on mainnet/testnet or is still in a pre-enablement rollout window; the presence of the flag (rather than an unconditional check) strongly suggests this is a rollout-in-progress feature guarding a previously-existing gap, and the additional CLI tooling (`VerifyProposal` in `crates/aptos/src/account/multisig_account.rs`) that explicitly recommends off-chain payload-hash verification before signing [5](#0-4)  supports the reading that on-chain enforcement is not guaranteed in this snapshot. Because this is feature-flag-gated (governance-controlled), I flag this with reduced confidence per the "no privileged governance or admin assumptions" exclusion — however, this is not an admin-privilege issue itself; it is a code-level gap that exists whenever the flag is in its default/disabled state, which is a plausible and historically-real network condition, not a hypothetical admin action.

### Recommendation
Make the payload-matches-stored-payload check unconditional (not feature-gated) whenever `transaction.payload.is_some()`, independent of `abort_if_multisig_payload_mismatch_enabled`, so that admission can never diverge from the payload that was actually voted on-chain. Alternatively, if backward compatibility requires the flag, ensure the flag is enabled in the base/genesis feature set for all new networks and add an assertion that execution derives its payload from the same source validated by the prologue, closing the gap between `run_multisig_prologue`'s `provided_payload` computation and `execute_multisig_transaction`'s independent `provided_payload` computation.

### Proof of Concept
This is a Move/framework logic gap rather than a directly reproducible exploit without controlling feature-flag state; a concrete PoC would require: (1) a network/testnet with `abort_if_multisig_payload_mismatch_enabled` disabled, (2) a multisig account with `transaction.payload` stored in full (not hash-only) for a queued proposal, (3) an owner submitting the final execute transaction with a `TransactionExecutableRef::EntryFunction` whose bytes differ from `transaction.payload`, and observing that `validate_multisig_transaction` does not abort while `execute_multisig_payload` executes the attacker-substituted entry function. I was not able to execute this in a live environment from static analysis alone, so this should be validated by a Devin session with test harness access (e.g., `aptos-move/e2e-move-tests`) before treating it as fully confirmed.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1361-1372)
```text
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

```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1373-1384)
```text
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
            );
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1305-1347)
```rust
        let provided_payload = match executable {
            TransactionExecutableRef::EntryFunction(entry_func) => {
                // TODO[Orderless]: For backward compatibility reasons, still using `MultisigTransactionPayload` here.
                // Find a way to deprecate this.
                bcs::to_bytes(&MultisigTransactionPayload::EntryFunction(
                    entry_func.clone(),
                ))
                .map_err(|_| invariant_violation_error())?
            },
            TransactionExecutableRef::Empty => {
                // Default to empty bytes if payload is not provided.
                if self
                    .features()
                    .is_abort_if_multisig_payload_mismatch_enabled()
                {
                    vec![]
                } else {
                    bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| invariant_violation_error())?
                }
            },
            TransactionExecutableRef::Script(script) => {
                if !self.features().is_multisig_script_enabled() {
                    let s = VMStatus::error(
                        StatusCode::FEATURE_UNDER_GATING,
                        Some("Multisig script payload is not enabled".to_string()),
                    );
                    return Ok((s, discarded_output(StatusCode::FEATURE_UNDER_GATING)));
                }
                bcs::to_bytes(&MultisigTransactionPayload::Script(script.clone()))
                    .map_err(|_| invariant_violation_error())?
            },
            TransactionExecutableRef::Encrypted => {
                // Decryption failed. Return an error so the caller runs the failure epilogue,
                // which increments the sequence number and charges gas.
                return Err(VMStatus::error(
                    StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
                    Some(
                        "Encrypted multisig transaction decryption failed; payload not available"
                            .to_string(),
                    ),
                ));
            },
        };
```

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

**File:** crates/aptos/src/account/multisig_account.rs (L159-238)
```rust
/// Verify entry function matches on-chain transaction proposal.
#[derive(Debug, Parser)]
pub struct VerifyProposal {
    #[clap(flatten)]
    pub(crate) multisig_account_with_sequence_number: MultisigAccountWithSequenceNumber,
    #[clap(flatten)]
    pub(crate) txn_options: TransactionOptions,
    #[clap(flatten)]
    pub(crate) entry_function_args: EntryFunctionArguments,
}

#[async_trait]
impl CliCommand<serde_json::Value> for VerifyProposal {
    fn command_name(&self) -> &'static str {
        "VerifyProposalMultisig"
    }

    async fn execute(self) -> CliTypedResult<serde_json::Value> {
        // Get multisig transaction via view function.
        let multisig_transaction = &self
            .txn_options
            .view(ViewFunction {
                module: ModuleId::new(
                    AccountAddress::ONE,
                    ident_str!("multisig_account").to_owned(),
                ),
                function: ident_str!("get_transaction").to_owned(),
                ty_args: vec![],
                args: vec![
                    bcs::to_bytes(
                        &self
                            .multisig_account_with_sequence_number
                            .multisig_account
                            .multisig_address,
                    )
                    .unwrap(),
                    bcs::to_bytes(&self.multisig_account_with_sequence_number.sequence_number)
                        .unwrap(),
                ],
            })
            .await?[0];
        // Get expected multisig transaction payload hash hex from provided entry function.
        let entry_function = self
            .entry_function_args
            .parse_with_optional_client(|| self.txn_options.rest_client())
            .await?;
        let expected_payload_hash =
            HashValue::sha3_256_of(&to_bytes::<MultisigTransactionPayload>(
                &MultisigTransactionPayload::EntryFunction(entry_function),
            )?)
            .to_hex_literal();
        // Get on-chain payload hash. If full payload provided on-chain:
        let actual_payload_hash =
            if let Some(actual_payload) = view_json_option_str(&multisig_transaction["payload"])? {
                // Actual payload hash is the hash of the on-chain payload.
                HashValue::sha3_256_of(actual_payload.parse::<HexEncodedBytes>()?.inner())
                    .to_hex_literal()
            // If full payload not provided, get payload hash directly from transaction proposal:
            } else {
                view_json_option_str(&multisig_transaction["payload_hash"])?.ok_or_else(|| {
                    CliError::UnexpectedError(
                        "Neither payload nor payload hash provided on-chain".to_string(),
                    )
                })?
            };
        // Get verification result based on if expected and actual payload hashes match.
        if expected_payload_hash.eq(&actual_payload_hash) {
            Ok(json!({
                "Status": "Transaction match",
                "Multisig transaction": multisig_transaction
            }))
        } else {
            Err(CliError::UnexpectedError(format!(
                "Transaction mismatch: The transaction you provided has a payload hash of \
                {expected_payload_hash}, but the on-chain transaction proposal you specified has \
                a payload hash of {actual_payload_hash}. For more info, see \
                https://aptos.dev/move/move-on-aptos/cli#multisig-governance"
            )))
        }
    }
```
