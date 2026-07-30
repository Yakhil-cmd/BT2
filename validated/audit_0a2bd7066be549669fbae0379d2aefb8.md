## Finding: WRITE-only Party permission holder can hijack ownership via TransferObjects (Owner field corruption bypassing TRANSFER/PublicTransfer/InternalTransfer permission)

### Summary
Party-owned objects define fine-grained permission bits (`Write`, `Delete`, `InternalTransfer`, `PublicTransfer`, `Wrap`) that are documented as being enforced "at the end of transaction execution" [1](#0-0) . In practice, neither the static-transaction typing verifier nor the execution `finish()` routine enforces these fine-grained permissions for the transfer/wrap/delete cases — only the coarse `MutableUsage` bit is checked, and the end-of-execution check is an unimplemented TODO.

### Finding Description
1. **Signing-time check is coarse.** In the static programmable-transactions typing verifier, `Context::new` computes `allow_by_value` purely from `can_use_mutably()`, not from `can_public_transfer()`/`can_internal_transfer()`: [2](#0-1) 
`check_by_value`, which gates `T::Command__::TransferObjects` object usage, only consults this `allow_by_value` flag: [3](#0-2) [4](#0-3) 
Since `ObjectPermissions::WRITE` already implies `MutableUsage` [5](#0-4) , an object owned with only `Write` (no `PublicTransfer`/`InternalTransfer`) passes this by-value check for `TransferObjects`.

2. **End-of-execution enforcement is not implemented.** The `finish()` routine, which is where the party.move docs say ownership-change authorization ("TRANSFER") should be checked, only verifies that the transaction sender equals the recorded owner — it does not compare `original_owner` against the new `written_objects` owner to detect an unauthorized transfer/wrap, as the comment explicitly states: [6](#0-5) 

3. **Corroborating TODO in the transaction-checks layer.** The `NonExclusiveWrite` mutability case for `Owner::Party` is explicitly unimplemented (`todo!("Party WIP")`), confirming the permission model for Party objects is only partially wired up: [7](#0-6) 

4. The pre-execution authentication step (`temporary_store/invariants.rs`) also only checks `can_use_mutably()` when deciding whether a Party-owned object is authenticated for mutation, again not distinguishing `Write` from `InternalTransfer`/`PublicTransfer`/`Wrap`: [8](#0-7) 

Taken together: a sender who only has `WRITE` permission on a Party object (no `PublicTransfer`/`InternalTransfer`) can include that object in `TransferObjects` with an arbitrary recipient address. The typing verifier allows the by-value move because it only checks `can_use_mutably()`. Execution proceeds to call `transfer_impl`, which unconditionally rewrites the object's `Owner`. At `finish()`, only sender==owner is confirmed; there is no check that the resulting `Owner` is consistent with the `TRANSFER`/`PublicTransfer` permission the docs promise. The object's `Owner` field is thus corrupted/hijacked to an address the sender was never authorized to transfer to.

### Impact Explanation
This is unauthorized change of an object's `Owner` field — a custody/ownership hijack achievable by any address holding only `WRITE` permission on a Party object, which the framework documents as explicitly NOT authorizing ownership changes. This matches the Critical bucket: "state corruption from unauthorized object ... transfer" reachable purely through public transaction submission (`TransferObjects` command), with no privileged party involved.

### Likelihood Explanation
High. This requires only: (1) a Party object owned with a permission set that includes `Write` but excludes `InternalTransfer`/`PublicTransfer` (a legitimate, supported configuration via `sui::party::set_permissions`/custom `Party` construction — not the "known-unsafe-initializer" exclusion, since it's the framework's granularity that's broken, not misuse), and (2) submitting a normal `TransferObjects` PTB command. No malicious validator, admin, or governance action is needed.

### Recommendation
- In `check_by_value` (`sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/input_arguments.rs`) and the corresponding v3 verifier, compute a permission-aware `allow_by_value`/command-specific check that requires `can_internal_transfer()`/`can_public_transfer()` (as appropriate for the transfer function invoked) for objects with `Owner::Party`, rather than generic `can_use_mutably()`.
- Implement the TODO in `finish()` (`sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs:2331-2337`): compare `original_owner` to the object's post-execution owner (and check deletions/wraps) against the sender's specific `Write`/`Delete`/`InternalTransfer`/`PublicTransfer`/`Wrap` permissions, aborting the transaction if an unauthorized owner/kind change occurred.
- Resolve the `todo!("Party WIP")` in `sui-transaction-checks/src/lib.rs` for `NonExclusiveWrite` mutability handling.

### Proof of Concept
1. Construct a Party object where the target sender's `Permissions` bitset is `WRITE` only (`ObjectPermission::Write | ObjectPermission::MutableUsage`), lacking `InternalTransfer`/`PublicTransfer`, via `sui::party::set_permissions` / a custom multi-member `Party` (not `single_owner`, which grants `ALL_PERMISSIONS`).
2. Transfer an object to this Party via `sui::transfer::public_party_transfer`.
3. As the WRITE-only sender, submit a PTB: input the Party object, then `TransferObjects([obj], @attacker)`.
4. Observe that typing verification passes (`allow_by_value` is true because `can_use_mutably()` is true), execution runs `transfer_impl`, and `finish()` only validates `sender == owner` without checking the transfer authorization — the object's `Owner` becomes `@attacker`, despite the sender never holding `PublicTransfer`/`InternalTransfer` permission.

*Note:* I was not able to trace every downstream code path (e.g., the exact native `transfer_impl`/object-runtime write-back and the `refined_permissions` computation in `loading/translate.rs`) within the available exploration budget; these should be reviewed to fully confirm no other gate exists between `check_by_value` and `finish()` that might narrow permissions per-command. Given the explicit TODO comment and the generic `can_use_mutably()`-only checks found in the verifier and invariants code, however, the vulnerability path is well supported by the code as written.

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/party.move (L12-22)
```text
/// The party can mutate the object, but not change its owner or delete it. This is checked at
/// end end of transaction execution.
const WRITE: u8 = 0x02;

/// The party can delete the object, but not otherwise modify it. This is checked at the end of
/// transaction execution.
const DELETE: u8 = 0x04;

/// The party can change the owner of the object, but not otherwise modify it. This is checked at
/// the end of transaction execution.
const TRANSFER: u8 = 0x08;
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/input_arguments.rs (L36-51)
```rust
impl Context {
    fn new(txn: &T::Transaction) -> Self {
        let objects = txn
            .objects
            .iter()
            .map(|object_input| {
                let allow_by_value = object_input.arg.refined_permissions.can_use_mutably();
                let allow_by_mut_ref = object_input.arg.refined_permissions.can_use_mutably();
                ObjectUsage {
                    allow_by_value,
                    allow_by_mut_ref,
                }
            })
            .collect();
        Self { objects }
    }
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/input_arguments.rs (L244-248)
```rust
        T::Command__::TransferObjects(objects, recipient) => {
            check_obj_usages(context, objects)?;
            check_obj_usage(context, recipient)?;
            // gas can be used by value in TransferObjects
        }
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/typing/verify/input_arguments.rs (L331-355)
```rust
fn check_by_value<E: ExecutionErrorTrait>(
    context: &mut Context,
    arg_idx: u16,
    location: &T::Location,
) -> Result<(), E> {
    match location {
        T::Location::GasCoin
        | T::Location::Result(_, _)
        | T::Location::TxContext
        | T::Location::WithdrawalInput(_)
        | T::Location::PureInput(_)
        | T::Location::ReceivingInput(_) => Ok(()),
        T::Location::ObjectInput(idx) => {
            if !context.objects.safe_get(*idx as usize)?.allow_by_value {
                Err(command_argument_error(
                    CommandArgumentError::InvalidObjectByValue,
                    arg_idx as usize,
                )
                .into())
            } else {
                Ok(())
            }
        }
    }
}
```

**File:** crates/sui-types/src/object.rs (L600-601)
```rust
    pub const WRITE: Self =
        Self::from_bits(ObjectPermission::Write as u64 | ObjectPermission::MutableUsage as u64);
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/execution/context.rs (L2306-2338)
```rust
    // Before finishing, enforce auth restrictions on consensus objects.
    for (id, original_owner) in consensus_owner_objects {
        let Owner::ConsensusAddressOwner { owner, .. } = original_owner else {
            panic!(
                "verified before adding to `consensus_owner_objects` that these are ConsensusAddressOwner"
            );
        };
        // Already verified in pre-execution checks that tx sender is the object owner.
        // Owner is allowed to do anything with the object.
        if tx_context.sender() != *owner {
            debug_fatal!(
                "transaction with a singly owned input object where the tx sender is not the owner should never be executed"
            );
            return Err(ExecutionError::new(
                ExecutionErrorKind::SharedObjectOperationNotAllowed,
                Some(
                    format!(
                        "Shared object operation on {} not allowed: \
                         transaction with singly owned input object must be sent by the owner",
                        id
                    )
                    .into(),
                ),
            ));
        }
        // If an Owner type is implemented with support for more fine-grained authorization,
        // checks should be performed here. For example, transfers and wraps can be detected
        // by comparing `original_owner` with:
        // let new_owner = written_objects.get(&id).map(|obj| obj.owner);
        //
        // Deletions can be detected with:
        // let deleted = deleted_object_ids.contains(&id);
    }
```

**File:** crates/sui-transaction-checks/src/lib.rs (L711-726)
```rust
                            SharedObjectMutability::Mutable => {
                                // TODO better error kind here
                                fp_ensure!(
                                    sender_permissions.can_use_mutably(),
                                    UserInputError::IncorrectUserSignature {
                                        error: format!(
                                            "Sender address {owner:?} does not have mutable access permissions for object {object_id:?} with party ownership. The required permission is {}, but the permissions for the sender for this object are {sender_permissions}",
                                            ObjectPermission::MutableUsage,
                                        ),
                                    }
                                )
                            }
                            SharedObjectMutability::NonExclusiveWrite => {
                                // TODO(Party WIP)
                                todo!("Party WIP")
                            }
```

**File:** sui-execution/latest/sui-adapter/src/temporary_store/invariants.rs (L624-633)
```rust
                    Owner::Party { permissions, .. } => {
                        let sender_permissions = permissions.permissions_for(sender);
                        let sponsor_permissions = sponsor
                            .as_ref()
                            .map(|s| permissions.permissions_for(s))
                            .unwrap_or(ObjectPermissions::NONE);
                        (sender_permissions | sponsor_permissions)
                            .can_use_mutably()
                            .then_some(id)
                    }
```
