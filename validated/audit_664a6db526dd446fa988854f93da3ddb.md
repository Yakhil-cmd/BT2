### Title
Gas-Key Nonce Exec-Fee Overcharged via Contract-Supplied Raw `public_key_len` Instead of Trie-ID Length — (File: `runtime/near-vm-runner/src/logic/logic.rs`, `runtime/near-vm-runner/src/wasmtime_runner/logic.rs`)

---

### Summary

When a smart contract calls the host functions `promise_batch_action_add_gas_key_with_full_access` or `promise_batch_action_add_gas_key_with_function_call`, the gas-key nonce exec fee is computed using the raw **borsh-encoded wire length** of the public key supplied by the contract (`public_key_len as usize`), rather than the **on-trie identifier length** (`public_key.trie_id_len()`). For an ML-DSA-65 post-quantum key these two values diverge by ~1920 bytes (1953 wire vs 33 on-trie). The contract controls `public_key_len` and can therefore supply an arbitrarily large value, causing the runtime to charge a massively inflated exec fee for the nonce-write step — or, conversely, a contract that passes a shorter-than-actual key length can underpay. The transaction-path (`permission_exec_fees` in `runtime/runtime/src/config.rs`) correctly calls `public_key.trie_id_len()`, so the two paths are inconsistent and the host-function path is the broken one.

---

### Finding Description

`gas_key_add_key_exec_fee` in `core/parameters/src/cost.rs` computes the per-nonce trie-write fee as:

```
nonce_key_len = access_key_key_len(account_id_len, public_key_len) + size_of::<NonceIndex>()
per_byte_fee  = gas_key_byte.exec_fee * (nonce_key_len + NONCE_VALUE_LEN) * num_nonces
```

The `public_key_len` argument is supposed to be the **on-trie** length of the key identifier (33 bytes for ed25519/ML-DSA-65, 65 bytes for secp256k1), because that is the actual number of bytes written to the trie for each nonce entry.

In the **transaction path** (`permission_exec_fees`, `runtime/runtime/src/config.rs` line 392), the call is:

```rust
gas_key_add_key_exec_fee(fees, account_id.len(), public_key.trie_id_len(), ...)
```

This is correct.

In the **host-function path** (`promise_batch_action_add_gas_key_with_full_access`, `logic.rs` line 3158, and `promise_batch_action_add_gas_key_with_function_call`, `logic.rs` line 3229), the call is:

```rust
gas_key_add_key_exec_fee(&self.fees_config, receiver_id.len(), public_key_len as usize, num_nonces)
```

Here `public_key_len` is the **raw byte count of the borsh-encoded public key as supplied by the contract in WASM memory** — not the trie-id length. For an ML-DSA-65 key the contract passes 1953 bytes; `trie_id_len()` would return 33. The same bug exists in the wasmtime runner (`wasmtime_runner/logic.rs` lines 3398 and 3502).

The correct value to pass is `public_key.trie_id_len()`, which is available after the `self.get_public_key(...)` / `get_public_key(...)` call that decodes the key.

---

### Impact Explanation

**Corrupted value:** The `gas_used` charged to the calling contract for the `promise_batch_action_add_gas_key_with_full_access` / `promise_batch_action_add_gas_key_with_function_call` host function call is wrong. For an ML-DSA-65 key with `N` nonces the overcharge per call is approximately:

```
(1953 - 33) bytes × N × gas_key_byte.exec_fee
```

With `gas_key_byte.exec_fee ≈ 47 683 715 gas/byte` and `N = 65535` (max `u16`), the overcharge is ~5.98 × 10¹⁵ gas — far exceeding the per-receipt gas limit (~300 Tgas), causing every such call to abort with `GasExceeded` even when the operation is economically cheap. This makes gas-key creation via contract calls **completely non-functional** for ML-DSA-65 keys.

Conversely, a contract that passes a shorter-than-actual `public_key_len` (e.g. 1 byte) would underpay the exec fee, undercharging the nonce-write cost and breaking the gas-accounting invariant.

**Scope:** VM/config selection and pre-inclusion transaction validation (gas accounting). The corrupted value is `gas_used` on the receipt, which determines whether the action is admitted and how much gas is refunded.

---

### Likelihood Explanation

- ML-DSA-65 (post-quantum) key support is a new protocol feature in this codebase.
- Any contract that calls `promise_batch_action_add_gas_key_with_full_access` or `promise_batch_action_add_gas_key_with_function_call` with an ML-DSA-65 public key will trigger the overcharge.
- The contract supplies `public_key_len` directly from WASM memory; it is fully attacker-controlled.
- The transaction path is correct, so the inconsistency is specific to the host-function path and will not be caught by transaction-level tests.
- The `test_gas_key_fee_parity_full_access` / `test_gas_key_fee_parity_function_call` integration tests compare gas burnt between the transaction and host-function paths, but only use ED25519 keys (where `len() == trie_id_len()`), so the divergence is invisible in existing tests.

---

### Recommendation

After `self.get_public_key(public_key_ptr, public_key_len)?` (which returns a decoded `PublicKey`), replace `public_key_len as usize` with `public_key.trie_id_len()` in both calls to `gas_key_add_key_exec_fee`:

**`runtime/near-vm-runner/src/logic/logic.rs`** (lines 3155–3160 and 3226–3231):
```rust
// Before:
let exec_fee = gas_key_add_key_exec_fee(
    &self.fees_config,
    receiver_id.len(),
    public_key_len as usize,   // ← wrong: borsh wire length
    num_nonces,
);

// After:
let exec_fee = gas_key_add_key_exec_fee(
    &self.fees_config,
    receiver_id.len(),
    public_key.trie_id_len(),  // ← correct: on-trie identifier length
    num_nonces,
);
```

Apply the same fix in **`runtime/near-vm-runner/src/wasmtime_runner/logic.rs`** (lines 3395–3400 and 3499–3504), using `public_key.trie_id_len()` after the key is decoded.

This aligns the host-function path with the transaction path in `permission_exec_fees` (`runtime/runtime/src/config.rs` line 392), which already correctly uses `public_key.trie_id_len()`.

---

### Proof of Concept

1. Deploy a contract that calls `promise_batch_action_add_gas_key_with_full_access` with a borsh-encoded ML-DSA-65 public key (1953 bytes) and `num_nonces = 1`.
2. The host function passes `public_key_len = 1953` to `gas_key_add_key_exec_fee`.
3. `nonce_key_len = access_key_key_len(account_id_len, 1953) + 2` ≈ `account_id_len + 1953 + 2 + 1` bytes.
4. `per_byte_fee = gas_key_byte.exec_fee × (nonce_key_len + 8)` — massively inflated vs the correct 33-byte trie-id path.
5. The transaction path for the same key uses `trie_id_len() = 33`, charging ~60× less gas for the same operation.
6. Observe that `test_gas_key_fee_parity_full_access` passes only because it uses ED25519 keys where `len() == trie_id_len() == 33`.

**Relevant code locations:**

- Broken host-function path (full-access): [1](#0-0) 
- Broken host-function path (function-call): [2](#0-1) 
- Broken wasmtime path (full-access): [3](#0-2) 
- Broken wasmtime path (function-call): [4](#0-3) 
- Correct transaction path using `trie_id_len()`: [5](#0-4) 
- `gas_key_add_key_exec_fee` definition showing `public_key_len` feeds `nonce_key_len`: [6](#0-5) 
- `trie_id_len()` vs `len()` divergence for ML-DSA-65: [7](#0-6) 
- Documentation confirming the invariant that all fee paths must use `trie_id_len()`: [8](#0-7)

### Citations

**File:** runtime/near-vm-runner/src/logic/logic.rs (L3155-3160)
```rust
        let exec_fee = gas_key_add_key_exec_fee(
            &self.fees_config,
            receiver_id.len(),
            public_key_len as usize,
            num_nonces,
        );
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L3226-3231)
```rust
        let exec_fee = gas_key_add_key_exec_fee(
            &self.fees_config,
            receipt_receiver_id.len(),
            public_key_len as usize,
            num_nonces,
        );
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L3395-3400)
```rust
    let exec_fee = gas_key_add_key_exec_fee(
        &ctx.fees_config,
        receiver_id.len(),
        public_key_len as usize,
        num_nonces,
    );
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/logic.rs (L3499-3504)
```rust
    let exec_fee = gas_key_add_key_exec_fee(
        &ctx.fees_config,
        receipt_receiver_id.len(),
        public_key_len as usize,
        num_nonces,
    );
```

**File:** runtime/runtime/src/config.rs (L389-395)
```rust
    let nonce_fee = gas_key_add_key_exec_fee(
        fees,
        account_id.len(),
        public_key.trie_id_len(),
        gas_key_info.num_nonces,
    );
    key_fee.checked_add(nonce_fee.total()).unwrap()
```

**File:** core/parameters/src/cost.rs (L879-897)
```rust
pub fn gas_key_add_key_exec_fee(
    cfg: &RuntimeFeesConfig,
    account_id_len: usize,
    public_key_len: usize,
    num_nonces: NonceIndex,
) -> GasKeyAddFee {
    let num_nonces = num_nonces as u64;
    let base =
        cfg.fee(ActionCosts::gas_key_nonce_write_base).exec_fee().checked_mul(num_nonces).unwrap();
    let nonce_key_len =
        access_key_key_len(account_id_len, public_key_len) + std::mem::size_of::<NonceIndex>();
    let per_byte = cfg
        .fee(ActionCosts::gas_key_byte)
        .exec_fee()
        .checked_mul((nonce_key_len + AccessKey::NONCE_VALUE_LEN) as u64)
        .unwrap()
        .checked_mul(num_nonces)
        .unwrap();
    GasKeyAddFee { base, per_byte }
```

**File:** core/crypto/src/signature.rs (L326-339)
```rust
    /// Length, in bytes, of the on-trie identifier for an access-key
    /// entry owned by this public key. For ed25519/secp256k1 this matches
    /// `len()`; for ML-DSA-65 the trie stores a SHA3-256 hash (33 bytes
    /// including the type tag), not the 1953-byte borsh-encoded pubkey.
    /// Used by storage-fee calculations on the runtime side; cheap to call
    /// (no hashing) - for ML-DSA-65 this returns the size of the digest
    /// form without actually hashing the pubkey.
    pub fn trie_id_len(&self) -> usize {
        match self {
            Self::ED25519(_) => 1 + ed25519_dalek::PUBLIC_KEY_LENGTH,
            Self::SECP256K1(_) => 1 + 64,
            Self::MLDSA65(_) => 1 + ML_DSA_65_HASH_LENGTH,
        }
    }
```

**File:** docs/architecture/how/post_quantum_signatures.md (L126-138)
```markdown
### 5. Storage usage and fee plumbing

The storage-stake calculation
(`runtime/runtime/src/access_keys.rs::access_key_storage_usage`) and the
gas-key fee helpers (`gas_key_*_fee` in `runtime/runtime/src/config.rs`) use
`PublicKey::trie_id_len()` rather than `PublicKey::len()`:

- `len()` reports the borsh-encoded length (33 / 65 / 1953 across the
  three `PublicKey` variants).
- `trie_id_len()` reports the on-trie length (33 / 65 / **33**).

The two diverge only for `PublicKey::MLDSA65`. Every storage-stake and
trie-byte-priced fee path was updated to call `trie_id_len()`.
```
