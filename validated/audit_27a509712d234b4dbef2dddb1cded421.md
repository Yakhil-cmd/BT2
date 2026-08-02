## Summary

The bug-class reduces to a single invariant: **the thing that gets executed must be cryptographically/structurally bound to the thing that was approved**, checked in the admission/prologue step, before any state-changing effects occur. The Solidity report showed a case where an approval check (`totalSupply()` gate) was checked against state that hadn't yet reflected the pending operation, letting a caller substitute a different outcome than what was validated.

I found a structurally identical gap in Aptos's multisig transaction admission flow: the multisig prologue can be configured (via a feature flag) to skip verifying that the entry-function payload actually being executed matches the payload that a quorum of owners voted to approve.

## Finding

**Title:** Multisig transaction execution can bypass co-owner-approved payload binding when `abort_if_multisig_payload_mismatch_enabled` is off - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Finding Description

A multisig transaction is proposed via `create_transaction`, which stores the **full payload on-chain** (as opposed to `create_transaction_with_hash`, which stores only a hash): [1](#0-0) 

Owners vote to approve/reject that stored transaction via `vote_transanction`/`approve_transaction`, which never re-validates the payload — it only records votes keyed by `sequence_number`: [2](#0-1) 

Execution is driven by a `Multisig` transaction the *executor* (any single owner) submits. Critically, the actual entry function/script that gets dispatched is taken directly from the **executor-supplied** `transaction_payload` field, not from anything re-fetched from chain: [3](#0-2) 

The VM's admission-time check (`validate_multisig_transaction`, invoked both as the transaction prologue during mempool validation and as the first execution step) is supposed to bind the executor-supplied payload to the on-chain-approved one. But when the full payload was stored on-chain (as opposed to just a hash), that binding check is gated behind the feature flag `abort_if_multisig_payload_mismatch_enabled` and an additional `!payload.is_empty()` condition: [4](#0-3) 

Specifically:
```
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) {
    let stored_payload = transaction.payload.borrow();
    assert!(payload == *stored_payload, error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH));
}
```
If the feature is disabled, this assertion never runs. The `provided_payload` passed into this check is computed from the transaction the executor is currently submitting (attacker/executor-controlled), via `run_multisig_prologue`: [5](#0-4) 

Everything else in the prologue (`assert_is_owner`, quorum count via `can_execute`/`can_be_executed`, timelock) validates that *some* transaction at that sequence number received enough approvals — it does **not** validate that the payload actually being run is the one that was approved, unless the flag is on. As a result, admission accepts a transaction whose executable content diverges from what the multisig owners consented to.

### Impact Explanation

This is a wrong-approval-set / broken-binding failure at the transaction admission boundary, matching the "Authenticator, WebAuthn, multisig, or approval validation accepting the wrong signing material or wrong approval set" pivot. The entire security property of a k-of-n multisig account is that k signers must agree on the *exact* action to be performed. If `abort_if_multisig_payload_mismatch_enabled` is not turned on, a single executing owner can:
1. Get co-owners to approve a proposal (e.g., "transfer 1 APT to X"), stored via `create_transaction`.
2. When executing, submit a `Multisig` transaction whose embedded `transaction_payload` is a completely different entry function (e.g., "add_owner(attacker)" or "transfer all funds to attacker") with the same `multisig_address`/sequence number.
3. `validate_multisig_transaction` accepts it because the quorum/timelock checks pass and the payload-equality assertion is skipped.
4. The VM executes the attacker/executor-chosen payload under the multisig account's signer authority — arbitrary state transition executed as the multisig account without the co-owners' actual consent.

This is a high/critical-severity confused-approval bug: unauthorized state transition under the wrong (mismatched) approval set for privileged multisig-controlled accounts (which often hold governance or treasury authority).

### Likelihood Explanation

Exploitability depends entirely on network configuration: it requires `abort_if_multisig_payload_mismatch_enabled` to be disabled for full-payload (non-hash) multisig proposals created via `create_transaction`. If the feature is enabled network-wide, the check runs and the bug is not reachable. I could not confirm from the indexed code whether this feature is on by default on mainnet/testnet in this repo snapshot (the flag definition lives in `aptos-move/framework/move-stdlib/sources/configs/features.move`, which I located but did not get to inspect for its default/enabled state before running out of iterations). This is a material caveat: **the actual exploitability of this finding hinges on that flag's current on-chain enablement status, which is unverified here.** Any deployment, devnet, or legacy account state where the flag is off (or was off historically and payloads created under a hash-mismatch-tolerant window) remains exposed.

### Recommendation

- Make the payload-match assertion for stored-payload multisig transactions unconditional (remove the feature gate), since skipping it defeats the core multisig guarantee.
- Alternatively, deprecate `create_transaction`'s "store full payload, validate optionally" mode entirely in favor of always requiring `create_transaction_with_hash` semantics (hash always stored, match always enforced).
- Audit historical/pending multisig transactions created while the flag was disabled to ensure no already-approved-but-unexecuted transactions can still be executed with a mismatched payload.

### Proof of Concept

1. Deploy/target a network where `abort_if_multisig_payload_mismatch_enabled` is disabled.
2. Owner A calls `multisig_account::create_transaction(owner_A, multisig_addr, payload_benign)` where `payload_benign` encodes `coin::transfer(multisig, victim, 1)`.
3. Owners B, C call `approve_transaction(owner, multisig_addr, seq)` until quorum is met, based on reviewing `payload_benign`.
4. Owner A (the executor) submits the actual `SignedTransaction` with `TransactionPayload::Multisig(Multisig { multisig_address: multisig_addr, transaction_payload: Some(MultisigTransactionPayload::EntryFunction(payload_malicious)) })`, where `payload_malicious` encodes e.g. `multisig_account::add_owner(multisig_signer, attacker_addr)` or a large fund transfer.
5. `validate_multisig_transaction` runs: `assert_is_owner` passes (A is owner), `can_execute`/`can_be_executed` passes (quorum met for sequence number `seq`), and because `abort_if_multisig_payload_mismatch_enabled()` is false, the `payload == *stored_payload` check is skipped.
6. The VM proceeds to execute `payload_malicious` as the multisig account signer — a transaction the other owners never approved. [6](#0-5)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1163-1183)
```text
    /// Create a multisig transaction, which will have one approval initially (from the creator).
    public entry fun create_transaction(
        owner: &signer,
        multisig_account: address,
        payload: vector<u8>,
    ) {
        assert!(payload.length() > 0, error::invalid_argument(EPAYLOAD_CANNOT_BE_EMPTY));

        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::some(payload),
            payload_hash: option::none<vector<u8>>(),
            votes: simple_map::create<address, bool>(),
            creator,
            creation_time_secs: now_seconds(),
        };
        add_transaction(creator, multisig_account, transaction);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1225-1253)
```text
    public entry fun vote_transanction(
        owner: &signer, multisig_account: address, sequence_number: u64, approved: bool) {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner_internal(owner, multisig_account_resource);

        assert!(
            multisig_account_resource.transactions.contains(sequence_number),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = multisig_account_resource.transactions.borrow_mut(sequence_number);
        let votes = &mut transaction.votes;
        let owner_addr = address_of(owner);

        if (votes.contains_key(&owner_addr)) {
            *votes.borrow_mut(&owner_addr) = approved;
        } else {
            votes.add(owner_addr, approved);
        };

        emit(
            Vote {
                multisig_account,
                owner: owner_addr,
                sequence_number,
                approved,
            }
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1385)
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
            );
        }
    }
```

**File:** types/src/transaction/multisig.rs (L12-63)
```rust
pub struct Multisig {
    pub multisig_address: AccountAddress,

    // Transaction payload is optional if already stored on chain.
    pub transaction_payload: Option<MultisigTransactionPayload>,
}

/// Enum for multisig transaction payloads, supporting both entry functions and scripts.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum MultisigTransactionPayload {
    EntryFunction(EntryFunction),
    Script(Script),
}

impl Multisig {
    pub fn as_multisig_payload(&self) -> MultisigPayload {
        MultisigPayload {
            multisig_address: self.multisig_address,
            entry_function_payload: self.transaction_payload.as_ref().and_then(|inner_payload| {
                match inner_payload {
                    MultisigTransactionPayload::EntryFunction(entry) => {
                        Some(entry.as_entry_function_payload())
                    },
                    MultisigTransactionPayload::Script(_) => None,
                }
            }),
        }
    }

    pub fn as_transaction_executable(&self) -> TransactionExecutable {
        match &self.transaction_payload {
            Some(MultisigTransactionPayload::EntryFunction(entry)) => {
                TransactionExecutable::EntryFunction(entry.clone())
            },
            Some(MultisigTransactionPayload::Script(script)) => {
                TransactionExecutable::Script(script.clone())
            },
            None => TransactionExecutable::Empty,
        }
    }

    pub fn as_transaction_executable_ref(&self) -> TransactionExecutableRef<'_> {
        match &self.transaction_payload {
            Some(MultisigTransactionPayload::EntryFunction(entry)) => {
                TransactionExecutableRef::EntryFunction(entry)
            },
            Some(MultisigTransactionPayload::Script(script)) => {
                TransactionExecutableRef::Script(script)
            },
            None => TransactionExecutableRef::Empty,
        }
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L419-479)
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
