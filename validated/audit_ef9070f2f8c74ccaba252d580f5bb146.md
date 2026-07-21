### Title
Nonce-free `compute_meta_tx_v0_hash` enables unlimited signature replay through the `meta_tx_v0` syscall — (File: `crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/transaction_hash/transaction_hash.cairo`)

### Summary

`compute_meta_tx_v0_hash` computes a transaction hash that is a pure, deterministic function of `(chain_id, contract_address, __execute__ selector, calldata)` with no nonce or per-invocation entropy. Any `(calldata, signature)` pair observed on-chain for a `meta_tx_v0` call can be replayed by any unprivileged caller, indefinitely, without the target account's consent. The OS explicitly skips nonce enforcement for version-0 transactions, and the injected `TxInfo` always carries `nonce = 0`, so no on-chain guard closes the gap.

### Finding Description

**Hash computation — Cairo OS layer**

`compute_meta_tx_v0_hash` delegates to `deprecated_get_transaction_hash` with `additional_data_size=0`:

```cairo
// transaction_hash.cairo lines 295–314
func compute_meta_tx_v0_hash{pedersen_ptr: HashBuiltin*}(
    contract_address: felt,
    entry_point_selector: felt,
    calldata: felt*,
    calldata_size: felt,
    chain_id: felt,
) -> felt {
    let (tx_hash) = deprecated_get_transaction_hash{hash_ptr=pedersen_ptr}(
        ...
        additional_data_size=0,          // ← no nonce
        additional_data=cast(0, felt*),
    );
    return tx_hash;
}
``` [1](#0-0) 

The resulting hash covers only `INVOKE_PREFIX | version=0 | contract_address | __execute__ | H(calldata) | max_fee=0 | chain_id`. No nonce, block number, or outer-transaction identifier is mixed in.

**Hash computation — Rust blockifier layer**

The Rust implementation in `syscall_base.rs` constructs an `InvokeTransactionV0` — a struct that has no nonce field — and calls `calculate_transaction_hash`:

```rust
// syscall_base.rs lines 318–328
let transaction_hash = InvokeTransactionV0 {
    max_fee: Fee(0),
    signature: signature.clone(),
    contract_address,
    entry_point_selector,
    calldata,
}
.calculate_transaction_hash(
    &self.context.tx_context.block_context.chain_info.chain_id,
    &signed_tx_version(&TransactionVersion::ZERO, ...),
)?;
``` [2](#0-1) 

`get_common_invoke_transaction_v0_hash` confirms no nonce is chained:

```rust
// transaction_hash.rs lines 317–334
HashChain::new()
    .chain(&INVOKE)
    .chain_if_fn(|| Some(transaction_version.0))   // version = 0
    .chain(transaction.contract_address.0.key())
    .chain(&transaction.entry_point_selector.0)
    .chain(&HashChain::new().chain_iter(transaction.calldata.0.iter()).get_pedersen_hash())
    .chain_if_fn(|| Some(transaction.max_fee.0.into()))  // max_fee = 0
    .chain(&Felt::try_from(chain_id)?)
    .get_pedersen_hash()
    // ← nonce never appears
``` [3](#0-2) 

**Injected `TxInfo` always carries `nonce = 0`**

The new execution context built in `execute_meta_tx_v0` (Cairo) and `meta_tx_v0` (Rust) hard-codes `nonce = 0`:

```cairo
// syscall_impls.cairo lines 348–368
tempvar new_tx_info = new TxInfo(
    version=0,
    ...
    transaction_hash=meta_tx_hash,
    nonce=0,          // ← always zero
    ...
);
``` [4](#0-3) 

```rust
// syscall_base.rs lines 333–343
let new_tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
    common_fields: CommonAccountFields {
        transaction_hash,
        version: TransactionVersion::ZERO,
        signature,
        nonce: Nonce(0.into()),   // ← always zero
        ...
    },
    max_fee: Fee(0),
});
``` [5](#0-4) 

**OS nonce gate is bypassed for version 0**

`check_and_increment_nonce` explicitly returns early for version-0 transactions:

```cairo
// execute_transaction_utils.cairo lines 63–67
func check_and_increment_nonce{...}(tx_info: TxInfo*) -> () {
    // Do not handle nonce for version 0.
    if (tx_info.version == 0) {
        return ();
    }
    ...
}
``` [6](#0-5) 

Because `meta_tx_v0` sets `version = 0`, the OS never increments or checks the target account's nonce. There is no sequencer-level guard that prevents the same `(calldata, signature)` from being submitted again.

### Impact Explanation

The `meta_tx_v0` syscall is the sequencer's meta-transaction primitive: a relayer outer-transaction calls a contract that invokes `meta_tx_v0`, which in turn calls the target account's `__execute__` entry point with a user-supplied signature. The target account's `__validate__` is **not** called; only `__execute__` runs, and it receives the deterministic `meta_tx_hash` as `tx_info.transaction_hash`.

Because the hash is identical for every replay of the same `(contract_address, calldata)` pair, a signature that was valid once remains valid forever. An attacker who extracts `(calldata, signature)` from any confirmed outer transaction can replay the inner `__execute__` call an unlimited number of times by submitting new outer transactions. If the target account's `__execute__` transfers tokens, changes storage, or emits L1 messages, each replay produces the same effect — unauthorized repeated execution without the account owner's consent.

This matches the allowed impact: **"High. Transaction conversion or signature/hash logic binds the wrong signer, hash, type, or executable payload."** and potentially **"Critical. Invalid or unauthorized Starknet transaction accepted through account validation, signature, nonce … logic"** depending on the target account's implementation.

### Likelihood Explanation

- The `meta_tx_v0` syscall is available to any contract during execution (blocked only in validate mode).
- All inputs needed for replay (`calldata`, `signature`) are visible in the outer transaction's calldata on-chain.
- No privileged access is required; any account with enough gas can submit the replaying outer transaction.
- Account contracts that rely on `tx_info.nonce` for replay protection receive `nonce = 0` every time and cannot distinguish a first call from a replay.

### Recommendation

Include per-invocation entropy in the meta-tx hash so that the same user signature cannot be reused across different outer transactions. Concretely, mix at least one of the following into `compute_meta_tx_v0_hash`:

- The outer transaction's nonce (accessible as `old_tx_info.nonce` in `execute_meta_tx_v0`).
- The outer transaction's hash (`old_tx_info.transaction_hash`).
- A monotonically increasing per-account counter stored in the target contract's state.

This mirrors the fix described in the external report: adding a nonce (salt) to the hash so that the same underlying intent produces a different hash — and therefore requires a fresh signature — for each invocation.

### Proof of Concept

1. Alice's account contract at address `A` is a meta-tx-capable account. She signs `sig_alice` over `meta_tx_hash = H(INVOKE, 0, A, __execute__, calldata_transfer_100_to_Bob, 0, chain_id)`.
2. A legitimate relayer submits outer transaction `T1` (nonce = 5) whose calldata encodes `meta_tx_v0(A, __execute__, calldata_transfer_100_to_Bob, sig_alice)`. The transfer executes.
3. An attacker reads `calldata_transfer_100_to_Bob` and `sig_alice` from `T1`'s calldata (public on-chain).
4. The attacker submits outer transaction `T2` (nonce = 0, from attacker's account) whose calldata encodes the same `meta_tx_v0(A, __execute__, calldata_transfer_100_to_Bob, sig_alice)`.
5. `compute_meta_tx_v0_hash` produces the identical hash (no nonce in the input). Alice's `__execute__` receives `transaction_hash = meta_tx_hash`, `nonce = 0`, `signature = sig_alice` — identical to step 2. Signature verification passes. The transfer executes again.
6. Steps 4–5 repeat until Alice's balance is drained.

The deterministic hash is confirmed by the test in `meta_tx.rs`, which shows `expected_meta_tx_hash` is computed solely from `(contract_address, __execute__ selector, calldata)` with no outer-transaction nonce: [7](#0-6)

### Citations

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/transaction_hash/transaction_hash.cairo (L295-314)
```text
func compute_meta_tx_v0_hash{pedersen_ptr: HashBuiltin*}(
    contract_address: felt,
    entry_point_selector: felt,
    calldata: felt*,
    calldata_size: felt,
    chain_id: felt,
) -> felt {
    let (tx_hash) = deprecated_get_transaction_hash{hash_ptr=pedersen_ptr}(
        tx_hash_prefix=INVOKE_HASH_PREFIX,
        version=0,
        contract_address=contract_address,
        entry_point_selector=entry_point_selector,
        calldata_size=calldata_size,
        calldata=calldata,
        max_fee=0,
        chain_id=chain_id,
        additional_data_size=0,
        additional_data=cast(0, felt*),
    );
    return tx_hash;
```

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L317-328)
```rust
        // Compute meta-transaction hash.
        let transaction_hash = InvokeTransactionV0 {
            max_fee: Fee(0),
            signature: signature.clone(),
            contract_address,
            entry_point_selector,
            calldata,
        }
        .calculate_transaction_hash(
            &self.context.tx_context.block_context.chain_info.chain_id,
            &signed_tx_version(&TransactionVersion::ZERO, &TransactionOptions { only_query }),
        )?;
```

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L333-343)
```rust
        let new_tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash,
                version: TransactionVersion::ZERO,
                signature,
                nonce: Nonce(0.into()),
                sender_address: contract_address,
                only_query,
            },
            max_fee: Fee(0),
        });
```

**File:** crates/starknet_api/src/transaction_hash.rs (L317-334)
```rust
fn get_common_invoke_transaction_v0_hash(
    transaction: &InvokeTransactionV0,
    chain_id: &ChainId,
    is_deprecated: bool,
    transaction_version: &TransactionVersion,
) -> Result<TransactionHash, StarknetApiError> {
    Ok(TransactionHash(
        HashChain::new()
            .chain(&INVOKE)
            .chain_if_fn(|| if !is_deprecated { Some(transaction_version.0) } else { None })
            .chain(transaction.contract_address.0.key())
            .chain(&transaction.entry_point_selector.0)
            .chain(&HashChain::new().chain_iter(transaction.calldata.0.iter()).get_pedersen_hash())
            .chain_if_fn(|| if !is_deprecated { Some(transaction.max_fee.0.into()) } else { None })
            .chain(&Felt::try_from(chain_id)?)
            .get_pedersen_hash(),
    ))
}
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/syscall_impls.cairo (L348-368)
```text
    tempvar new_tx_info = new TxInfo(
        version=0,
        account_contract_address=contract_address,
        max_fee=0,
        signature_start=request.signature_start,
        signature_end=request.signature_end,
        transaction_hash=meta_tx_hash,
        chain_id=old_tx_info.chain_id,
        nonce=0,
        resource_bounds_start=cast(0, ResourceBounds*),
        resource_bounds_end=cast(0, ResourceBounds*),
        tip=0,
        paymaster_data_start=cast(0, felt*),
        paymaster_data_end=cast(0, felt*),
        nonce_data_availability_mode=0,
        fee_data_availability_mode=0,
        account_deployment_data_start=cast(0, felt*),
        account_deployment_data_end=cast(0, felt*),
        proof_facts_start=cast(0, felt*),
        proof_facts_end=cast(0, felt*),
    );
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/execute_transaction_utils.cairo (L63-67)
```text
func check_and_increment_nonce{contract_state_changes: DictAccess*}(tx_info: TxInfo*) -> () {
    // Do not handle nonce for version 0.
    if (tx_info.version == 0) {
        return ();
    }
```

**File:** crates/blockifier/src/execution/syscalls/syscall_tests/meta_tx.rs (L102-113)
```rust
    let expected_meta_tx_hash = InvokeTransactionV0 {
        max_fee: Fee(0),
        signature: Default::default(),
        contract_address,
        entry_point_selector: selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        calldata: calldata!(argument),
    }
    .calculate_transaction_hash(
        &CHAIN_ID_FOR_TESTS.clone(),
        &signed_tx_version(&TransactionVersion::ZERO, &TransactionOptions { only_query }),
    )
    .unwrap();
```
