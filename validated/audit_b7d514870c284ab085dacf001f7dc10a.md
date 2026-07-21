The code is directly readable and the logic is unambiguous. Let me confirm the exact behavior.

### Title
Cache Bypass in `get_or_allocate_tx_info_start_ptr` Allocates a Fresh VM Segment on Every `get_tx_info` Call for v1-Bound Cairo0 Accounts — (`crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs`)

---

### Summary

When a v3 transaction is sent from an account whose `class_hash` is in `v1_bound_accounts_cairo0` and whose `tip ≤ v1_bound_accounts_max_tip`, the function `get_or_allocate_tx_info_start_ptr` takes an early-return path that **never writes to `self.tx_info_start_ptr`**. As a result, every invocation of the `get_tx_info` syscall within the same entry-point execution allocates a brand-new read-only VM segment and returns a distinct `Relocatable` address. The `self.tx_info_start_ptr` cache is completely bypassed for this code path.

---

### Finding Description

The normal (non-v1-bound) path correctly caches the allocated pointer:

```rust
match self.tx_info_start_ptr {
    Some(tx_info_start_ptr) => Ok(tx_info_start_ptr),   // cache hit
    None => {
        let tx_info_start_ptr = self.allocate_tx_info_segment(vm, None)?;
        self.tx_info_start_ptr = Some(tx_info_start_ptr); // cache write
        Ok(tx_info_start_ptr)
    }
}
```

The v1-bound path, however, calls `allocate_tx_info_segment` and returns immediately, **without ever touching `self.tx_info_start_ptr`**:

```rust
if version == TransactionVersion::THREE && v1_bound_accounts.contains(&self.class_hash) {
    // ...
    if tip <= versioned_constants.os_constants.v1_bound_accounts_max_tip {
        let modified_version = signed_tx_version(...);
        return self.allocate_tx_info_segment(vm, Some(modified_version)); // no cache write
    }
}
```

The code comment at line 324 even acknowledges this explicitly: *"In such a case, `self.tx_info_start_ptr` is not used."*

`allocate_tx_info_segment` calls `self.read_only_segments.allocate(vm, &tx_info)` each time, which appends a new segment to the VM's memory model and returns a fresh `Relocatable` with a new segment index. Two consecutive `get_tx_info` calls therefore return, e.g., `(5, 0)` and `(6, 0)` — different addresses pointing to segments with **identical content** (same version=1, sender, fee, signature ptr, hash, chain_id, nonce). [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

The concrete wrong value is the `tx_info_start_ptr` itself. Any Cairo0 contract in `v1_bound_accounts_cairo0` that calls `get_tx_info` more than once in a single entry-point execution receives a different pointer on each call. Consequences:

1. **Pointer-identity checks fail**: A contract that caches the first pointer and later asserts `ptr1 == ptr2` (a reasonable sanity check) will observe a mismatch and may revert or branch incorrectly.
2. **RPC simulation/fee estimation diverges from on-chain execution**: If the OS or prover enforces that `get_tx_info` returns a stable pointer (as the non-v1-bound path guarantees), simulation results will differ from what the OS would produce, making fee estimates and simulation traces authoritative-looking but wrong.
3. **Unbounded segment growth**: Each `get_tx_info` call in the v1-bound path appends a new read-only segment. A contract that calls `get_tx_info` in a loop inflates VM memory, skewing gas/resource accounting.

The impact falls squarely within: *"High. RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."* [4](#0-3) 

---

### Likelihood Explanation

The trigger requires no privileges:
- The attacker (or any user) deploys or uses an account whose `class_hash` is already in `v1_bound_accounts_cairo0` (a fixed set of known wallet class hashes, e.g., Argent/Braavos Cairo0 variants).
- They send a v3 transaction with `tip ≤ v1_bound_accounts_max_tip` (the default/zero tip satisfies this).
- The account contract calls `get_tx_info` more than once in its `__validate__` or `__execute__` entry point.

This is a realistic scenario for any wallet that calls `get_tx_info` in both validation and execution phases, or calls it twice within one phase. [5](#0-4) 

---

### Recommendation

Store the result in `self.tx_info_start_ptr` even in the v1-bound path, so subsequent calls return the same pointer:

```rust
if tip <= versioned_constants.os_constants.v1_bound_accounts_max_tip {
    let modified_version = signed_tx_version(
        &TransactionVersion::ONE,
        &TransactionOptions { only_query: tx_context.tx_info.only_query() },
    );
    // Cache the result so repeated calls return the same pointer.
    let ptr = self.allocate_tx_info_segment(vm, Some(modified_version))?;
    self.tx_info_start_ptr = Some(ptr);
    return Ok(ptr);
}
```

This mirrors the behavior of the non-v1-bound path and of `get_or_allocate_tx_signature_segment`. [6](#0-5) 

---

### Proof of Concept

A Rust unit test outline (production logic, no mocks needed beyond a minimal state):

1. Construct a `DeprecatedSyscallHintProcessor` with:
   - `class_hash` set to any value in `versioned_constants.os_constants.v1_bound_accounts_cairo0`
   - A `TransactionInfo::Current` with `version = THREE` and `tip = Tip(0)` (≤ `v1_bound_accounts_max_tip`)
2. Call `get_or_allocate_tx_info_start_ptr(&mut vm)` → record `ptr1`.
3. Call `get_or_allocate_tx_info_start_ptr(&mut vm)` again → record `ptr2`.
4. Assert `ptr1 == ptr2` — **this assertion fails** with the current code because `ptr2.segment_index == ptr1.segment_index + 1`.
5. Confirm `self.tx_info_start_ptr` remains `None` after both calls. [7](#0-6)

### Citations

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L232-235)
```rust
    // Transaction info. and signature segments; allocated on-demand.
    tx_signature_start_ptr: Option<Relocatable>,
    tx_info_start_ptr: Option<Relocatable>,
}
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L297-309)
```rust
    pub fn get_or_allocate_tx_signature_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> DeprecatedSyscallResult<Relocatable> {
        match self.tx_signature_start_ptr {
            Some(tx_signature_start_ptr) => Ok(tx_signature_start_ptr),
            None => {
                let tx_signature_start_ptr = self.allocate_tx_signature_segment(vm)?;
                self.tx_signature_start_ptr = Some(tx_signature_start_ptr);
                Ok(tx_signature_start_ptr)
            }
        }
    }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L319-338)
```rust
        // The set of v1-bound-accounts.
        let v1_bound_accounts = &versioned_constants.os_constants.v1_bound_accounts_cairo0;

        // If the transaction version is 3 and the account is in the v1-bound-accounts set,
        // the syscall should return transaction version 1 instead.
        // In such a case, `self.tx_info_start_ptr` is not used.
        if version == TransactionVersion::THREE && v1_bound_accounts.contains(&self.class_hash) {
            let tip = match &tx_context.tx_info {
                TransactionInfo::Current(transaction_info) => transaction_info.tip,
                TransactionInfo::Deprecated(_) => {
                    panic!("Transaction info variant doesn't match transaction version")
                }
            };
            if tip <= versioned_constants.os_constants.v1_bound_accounts_max_tip {
                let modified_version = signed_tx_version(
                    &TransactionVersion::ONE,
                    &TransactionOptions { only_query: tx_context.tx_info.only_query() },
                );
                return self.allocate_tx_info_segment(vm, Some(modified_version));
            }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L341-348)
```rust
        match self.tx_info_start_ptr {
            Some(tx_info_start_ptr) => Ok(tx_info_start_ptr),
            None => {
                let tx_info_start_ptr = self.allocate_tx_info_segment(vm, None)?;
                self.tx_info_start_ptr = Some(tx_info_start_ptr);
                Ok(tx_info_start_ptr)
            }
        }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L366-387)
```rust
    fn allocate_tx_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
        tx_version_override: Option<TransactionVersion>,
    ) -> DeprecatedSyscallResult<Relocatable> {
        let tx_signature_start_ptr = self.get_or_allocate_tx_signature_segment(vm)?;
        let TransactionContext { block_context, tx_info } = self.context.tx_context.as_ref();
        let tx_signature_length = tx_info.signature().0.len();
        let tx_version = tx_version_override.unwrap_or(tx_info.signed_version());
        let tx_info: Vec<MaybeRelocatable> = vec![
            tx_version.0.into(),
            (*tx_info.sender_address().0.key()).into(),
            Felt::from(tx_info.max_fee_for_execution_info_syscall().0).into(),
            tx_signature_length.into(),
            tx_signature_start_ptr.into(),
            tx_info.transaction_hash().0.into(),
            Felt::from_hex(block_context.chain_info.chain_id.as_hex().as_str())?.into(),
            tx_info.nonce().0.into(),
        ];

        let tx_info_start_ptr = self.read_only_segments.allocate(vm, &tx_info)?;
        Ok(tx_info_start_ptr)
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L736-744)
```rust
    fn get_tx_info(
        _request: GetTxInfoRequest,
        vm: &mut VirtualMachine,
        syscall_handler: &mut Self,
    ) -> DeprecatedSyscallResult<GetTxInfoResponse> {
        let tx_info_start_ptr = syscall_handler.get_or_allocate_tx_info_start_ptr(vm)?;

        Ok(GetTxInfoResponse { tx_info_start_ptr })
    }
```
