No vulnerability found for this question.

**Reasoning:** `current_weight` in `runtime/near-vm-runner/src/cache.rs` is purely an internal bookkeeping counter for the `LruWeightedCache`'s total tracked byte weight, used only for eviction decisions and metrics reporting [1](#0-0) . It has no role in determining which compiled artifact is returned for a given key — lookups (`get`, `try_lookup`) are keyed strictly by exact `CryptoHash` match through `lru::LruCache`/`HashMap`, independent of the weight value [2](#0-1) .

The actual cache key that determines which compiled code is served is produced by `get_contract_cache_key`, which hashes `code_hash` (the hash of the actual wasm bytes) together with `vm_config_non_crypto_hash`, `vm_kind`, and `vm_hash` via `CryptoHash::hash_borsh` [3](#0-2) . For two distinct attacker-controlled contracts to collide on this key, an attacker would need a second-preimage/collision on the underlying cryptographic hash (SHA-256-based `CryptoHash`), which is computationally infeasible and not a bug in this code path.

Since `current_weight` doesn't participate in key derivation or artifact selection, and the actual key derivation relies on a cryptographic hash whose collision resistance is a standard security assumption (not violated by any logic in this file), there is no demonstrated exploitable path from an unprivileged attacker's `DeployContract`/call actions to serving one contract's compiled code for another contract's cache key.

### Citations

**File:** runtime/near-vm-runner/src/cache.rs (L39-65)
```rust
enum ContractCacheKey {
    _Version1,
    _Version2,
    _Version3,
    _Version4,
    Version5 {
        code_hash: CryptoHash,
        vm_config_non_crypto_hash: u64,
        vm_kind: near_parameters::vm::VMKind,
        vm_hash: u64,
    },
}

#[cfg(feature = "wasmtime_vm")]
pub(crate) fn get_contract_cache_key(
    code_hash: CryptoHash,
    config: &Config,
    vm_hash: u64,
) -> CryptoHash {
    let key = ContractCacheKey::Version5 {
        code_hash,
        vm_config_non_crypto_hash: config.non_crypto_hash(),
        vm_kind: config.vm_kind,
        vm_hash,
    };
    CryptoHash::hash_borsh(key)
}
```

**File:** runtime/near-vm-runner/src/cache.rs (L924-932)
```rust
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    fn len(&self) -> usize {
        self.cache.len()
    }

    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    fn current_weight(&self) -> u64 {
        self.current_weight
    }
```

**File:** runtime/near-vm-runner/src/cache.rs (L1028-1050)
```rust
    pub fn try_lookup<E, R>(
        &self,
        key: CryptoHash,
        generate: impl FnOnce() -> Result<(u64, Box<AnyCacheValue>), E>,
        with: impl FnOnce(&AnyCacheValue) -> R,
    ) -> Result<R, E> {
        let Some(cache) = &self.cache else {
            let (_, v) = generate()?;
            // NB: The stars and ampersands here are semantics-affecting. e.g. if the star is
            // missing, we end up making an object out of `Box<dyn ...>` rather than using `dyn
            // Any` within the box which is obviously quite wrong.
            return Ok(with(&*v));
        };
        {
            if let Some((_weight, cached_value)) = cache.lock().get(&key) {
                // Same here.
                return Ok(with(&**cached_value));
            }
        }
        let (weight, generated) = generate()?;
        let result = with(&*generated);
        let mut locked = cache.lock();
        locked.put(key, weight, generated);
```
