### Title
Preimage Type Confusion in Shared Cache Allows Bytecode Bytes to Be Decoded as Account Properties — (`File: basic_system/src/system_implementation/flat_storage_model/preimage_cache.rs`)

---

### Summary

`BytecodeAndAccountDataPreimagesStorage` stores both `PreimageType::Bytecode` and `PreimageType::AccountData` preimages in a single `BTreeMap<Bytes32, UsizeAlignedByteBox>` keyed only by hash. On a cache hit, the `preimage_type` field is silently ignored and the cached bytes are returned regardless of the requested type. An oracle-data-influencing caller (malicious sequencer) can exploit this by deploying a contract whose full bytecode preimage is exactly `AccountProperties::ENCODED_SIZE` bytes long, then providing that bytecode hash as the account-properties hash for a victim account. The cache returns the bytecode bytes as account properties, causing `AccountProperties::decode` to interpret attacker-controlled bytecode content as nonce, balance, and bytecode-hash fields — a direct state-transition corruption.

---

### Finding Description

`BytecodeAndAccountDataPreimagesStorage::expose_preimage` has two branches:

**Cache-miss path (lines 107–180):** fetches from the oracle, optionally verifies `Blake2s256(preimage) == hash` in `PROOF_ENV`, then stores the result.

**Cache-hit path (lines 101–106):**

```rust
if let Some(cached) = self.storage.get(hash) {
    unsafe {
        let cached: &'static [u8] = core::mem::transmute(cached.as_slice());
        Ok(cached)
    }
}
```

The `preimage_type` argument is **completely ignored** on a cache hit. The comment at line 222 confirms this is intentional:

```rust
// preimage type is not important in our case, we do not version them yet
```

Both `PreimageType::Bytecode` and `PreimageType::AccountData` use the same hash function (Blake2s256) and share the same `BTreeMap`. If hash `H` is first inserted as bytecode content, a subsequent `AccountData` request for the same `H` returns the bytecode bytes without any type check or re-verification.

The account materialization path in `NewModelAccountCache::materialize_element` (lines 233–250) calls:

```rust
let preimage = preimages_cache.get_preimage::<PROOF_ENV>(
    ee_type,
    &PreimageRequest {
        hash,
        expected_preimage_len_in_bytes: AccountProperties::ENCODED_SIZE as u32,
        preimage_type: PreimageType::AccountData,
    },
    ...
)?;
assert_eq!(preimage.len(), AccountProperties::ENCODED_SIZE);
AccountProperties::decode(preimage.try_into()...)
```

`AccountProperties::ENCODED_SIZE` is 124 bytes (confirmed by the pubdata test comment: `1 + 8 + 1 + 2 + 4 + bytecode_len + 4 + 4`). A bytecode of `unpadded_code_len = 117` bytes produces `full_bytecode_len() = 117 + 7 (padding) + 0 (artifacts) = 124` bytes — exactly matching `AccountProperties::ENCODED_SIZE`. The `assert_eq!` passes, and `AccountProperties::decode` interprets the attacker-crafted bytecode bytes as account properties.

---

### Impact Explanation

An attacker who can influence oracle data (malicious sequencer / oracle-data-influencing caller) can:

1. Deploy a contract with exactly 117 bytes of crafted bytecode `B`. The stored preimage is `B || 7-byte-padding` = 124 bytes, cached under `H = Blake2s256(B || padding)`.
2. Provide `H` as the `AccountAggregateDataHash` for a victim account (the account-properties hash slot at `(ACCOUNT_PROPERTIES_STORAGE_ADDRESS, victim_address)`).
3. When the victim account is materialized, `get_preimage(hash=H, type=AccountData, expected_len=124)` hits the cache and returns the 124-byte bytecode preimage.
4. `AccountProperties::decode` reads those bytes as: `versioning_data` (8 bytes), `nonce` (8 bytes), `balance` (32 bytes), `bytecode_hash` (32 bytes), `observable_bytecode_hash` (32 bytes), `unpadded_code_len` (4 bytes), `observable_bytecode_len` (4 bytes), `artifacts_len` (4 bytes).

By crafting the bytecode content, the attacker fully controls the decoded `balance`, `nonce`, and `bytecode_hash` of the victim account. This enables:
- **Balance inflation** (arbitrary ETH minting for the victim account)
- **Nonce manipulation** (replay-attack enablement or nonce exhaustion)
- **Bytecode hash substitution** (redirecting execution to attacker-controlled code)

This is a critical state-transition correctness bug.

---

### Likelihood Explanation

The attacker role is an oracle-data-influencing caller (sequencer), which is explicitly listed in the Immunefi scope. The oracle is documented as untrusted throughout the codebase:

> "Oracle responses are non-deterministic and MUST be treated as untrusted input."

The attack requires:
1. Deploying a 117-byte contract (trivial — any EVM bytecode of that length works).
2. Providing the resulting bytecode hash as an account-properties hash (one oracle response substitution).

No cryptographic assumptions are broken. The attack is deterministic and reproducible.

---

### Recommendation

The cache must be keyed by `(hash, preimage_type)` rather than `hash` alone, or the cache-hit path must validate that the stored entry's type matches the requested type:

```rust
// Option A: key by (hash, type)
pub(crate) storage: BTreeMap<(Bytes32, PreimageType), UsizeAlignedByteBox<A>, A>,

// Option B: store type alongside bytes and check on hit
if let Some((cached_type, cached)) = self.storage.get(hash) {
    if *cached_type != preimage_type {
        return Err(internal_error!("Preimage type mismatch").into());
    }
    ...
}
```

Additionally, remove the comment "preimage type is not important in our case" — it is security-critical.

---

### Proof of Concept

**Setup:**
- Attacker deploys a contract with 117-byte bytecode `B` crafted so that bytes 8–16 encode a large nonce, bytes 16–48 encode `U256::MAX` as balance, and bytes 48–80 encode an attacker-controlled bytecode hash.
- The system stores `H = Blake2s256(B || [0u8;7])` in the preimage cache as `PreimageType::Bytecode`.

**Trigger:**
- Attacker (as sequencer) provides `H` as the value at storage slot `(ACCOUNT_PROPERTIES_STORAGE_ADDRESS, victim_address)` via the oracle.

**Execution:**
1. `materialize_element` reads `hash = H` from the account-properties storage slot.
2. Calls `get_preimage(hash=H, type=AccountData, expected_len=124)`.
3. Cache hit at line 101 — returns the 124-byte bytecode preimage `B || [0u8;7]`.
4. `assert_eq!(124, 124)` passes.
5. `AccountProperties::decode` reads `balance = U256::MAX` from bytes 16–48.
6. Victim account now has `U256::MAX` balance in the system's state.

**Relevant code locations:**

Cache-hit bypass (no type check): [1](#0-0) 

Explicit acknowledgment that type is ignored: [2](#0-1) 

Account materialization decoding the preimage as `AccountProperties`: [3](#0-2) 

`PreimageType` enum (both variants use Blake2s256, same hash function): [4](#0-3) 

Shared single-map storage (no type dimension in key): [5](#0-4)

### Citations

**File:** basic_system/src/system_implementation/flat_storage_model/preimage_cache.rs (L33-38)
```rust
pub struct BytecodeAndAccountDataPreimagesStorage<R: Resources, A: Allocator + Clone = Global> {
    pub(crate) storage: BTreeMap<Bytes32, UsizeAlignedByteBox<A>, A>,
    pub(crate) publication_storage: NewPreimagesPublicationStorage<A>,
    pub(crate) allocator: A,
    _marker: PhantomData<R>,
}
```

**File:** basic_system/src/system_implementation/flat_storage_model/preimage_cache.rs (L101-106)
```rust
        if let Some(cached) = self.storage.get(hash) {
            unsafe {
                let cached: &'static [u8] = core::mem::transmute(cached.as_slice());

                Ok(cached)
            }
```

**File:** basic_system/src/system_implementation/flat_storage_model/preimage_cache.rs (L222-222)
```rust
        // preimage type is not important in our case, we do not version them yet
```

**File:** basic_system/src/system_implementation/flat_storage_model/account_cache.rs (L233-250)
```rust
                        let preimage = preimages_cache.get_preimage::<PROOF_ENV>(
                            ee_type,
                            &PreimageRequest {
                                hash,
                                expected_preimage_len_in_bytes: AccountProperties::ENCODED_SIZE
                                    as u32,
                                preimage_type: PreimageType::AccountData,
                            },
                            &mut inf_resources,
                            oracle,
                        )?;
                        // it's redundant as preimages cache should just check it, but why not
                        assert_eq!(preimage.len(), AccountProperties::ENCODED_SIZE);

                        AccountProperties::decode(preimage.try_into().map_err(|_| {
                            internal_error!("Unexpected preimage length for AccountProperties")
                        })?)
                    }
```

**File:** zk_ee/src/common_structs/new_preimages_publication_storage.rs (L14-17)
```rust
pub enum PreimageType {
    Bytecode = 0,
    AccountData = 1,
}
```
