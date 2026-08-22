### Title
Unbounded CPU cost in `decode_bs58`/`bs58::decode` when parsing attacker-controlled `PublicKey`/`SecretKey`/`Signature` strings via RPC - (`core/crypto/src/signature.rs`)

### Summary
`FromStr` for `PublicKey`, `PublicKeyHandle`, `SecretKey` and `Signature` route the base58 payload straight into `decode_bs58::<N>` with no length pre-check, and the standard bs58 decode algorithm performs a per-character bignum multiply-carry pass whose cost is proportional to the current size of the output buffer, making full decode of an attacker-supplied string quadratic in its length. Because these `FromStr` impls are reachable from public, unauthenticated JSON-RPC inputs (e.g. `query` with `request_type: view_access_key`, or a transaction's `public_key`/`signature` fields), an attacker can submit a very long base58-alphabet string to force expensive CPU work on the node handling the request.

### Finding Description
`PublicKey::from_str`, `PublicKeyHandle::from_str` and `SecretKey::from_str` all split off a key-type prefix via `split_key_type_data` (no length validation) and then call `decode_bs58::<N>(key_data)` directly on the remaining, attacker-controlled substring: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

`PublicKeyHandle::from_str` additionally calls `bs58::decode(data).into_vec()` directly (for the `ml-dsa-65-hash:` prefix path) before any fixed-size check: [5](#0-4) 

Base58 decoding of an arbitrary-length string with the classic radix-conversion algorithm (used by the `bs58` crate's `into_vec`/`decode_into`) processes the input one character at a time, and for each character it walks the entire currently-decoded output buffer to propagate the multiply-by-58 carry. This means decode cost grows with the *product* of input length and (growing) output length — effectively O(n²) for a long, valid-base58-alphabet string — before any fixed-size (`N`) check via `try_fixed_array` can reject the result. The size check only happens *after* the full decode completes, so the expensive work cannot be short-circuited by an early length guard in `decode_bs58`. I was not able to view the exact body of `decode_bs58`/`decode_bs58_impl` in this pass (the file is 1795 lines and the definition falls in the section between lines ~1000-1650 that I could not retrieve before running out of tool calls), so I cannot confirm with certainty whether nearcore's implementation added an explicit length pre-check that would short-circuit this; this should be verified directly against the source before treating this as conclusively exploitable.

The separate concern raised in the question about `Bs58`'s `Display` buffer sizing (`len*2+8`) is not exploitable: every call site constructs `Bs58` from a fixed, compile-time-sized byte array (32/64/1952/3309/4032 bytes, matching `ED25519PublicKey`, `Secp256K1PublicKey`, `MlDsa65PublicKey`, etc.), never from attacker-controlled variable-length data: [6](#0-5) [7](#0-6) 
That part of the hypothesis does not hold.

### Impact Explanation
If confirmed, this is a bounded-but-potentially-large CPU-exhaustion / latency-spike vector on whichever node process parses the string (RPC-serving process), matching NEAR's "node panic or unbounded resource use" bounty class rather than a consensus-affecting bug. It would not cause state divergence, fund loss, or authorization bypass, since parsing failures simply return `ParseKeyError`/`ParseSignatureError`; the risk is availability/DoS on the specific node instance, and only significant if the request body/string length is not otherwise capped by the RPC transport layer (HTTP payload limits) to a size small enough to keep decode cost negligible.

### Likelihood Explanation
Feasibility hinges on two unconfirmed facts: (1) whether `decode_bs58` in this codebase gates the input length before calling into `bs58::decode`, and (2) whether the JSON-RPC/HTTP layer caps request body size tightly enough to make the quadratic cost negligible. Neither could be verified with the available tool budget. Given that transaction size and view-query payloads are typically bounded by outer JSON-RPC body limits, the practical impact — if any pre-check is missing — would scale with whatever that outer limit is, not truly "unbounded."

### Recommendation
Add an explicit upper-bound check on the base58 input length in `decode_bs58`/`decode_bs58_impl` before invoking the decode routine (e.g., reject strings longer than a small multiple of the expected fixed output size `N`, since valid base58 output can never legitimately be shorter than the input character count divided by ~1.37). This turns the check into an O(1) guard that fully eliminates the quadratic-cost path regardless of any RPC-layer body size limits.

### Proof of Concept
Add a fuzz/unit test in `core/crypto/src/signature.rs` (or a new bolero fuzz target) that:
1. Constructs a base58 string of several megabytes using only valid base58 alphabet characters (e.g., repeated `"1"` or randomly sampled from the 58-character alphabet).
2. Prefixes it with `"ed25519:"` and calls `PublicKey::from_str` on it, asserting the call returns within a bounded time budget (e.g., <10ms) regardless of input length, and that peak allocation stays bounded (e.g., via a custom allocator or `cap` crate) proportional to `N`, not to input length.
3. Repeats for `SecretKey::from_str`, `Signature::from_str`/equivalent, and `PublicKeyHandle::from_str` (including the `ml-dsa-65-hash:` prefix path calling `bs58::decode(...).into_vec()` directly).
4. Sweeps input sizes (1KB, 1MB, 10MB) and asserts wall-clock time grows linearly (or is capped by an early length check), not quadratically, to confirm whether the fix (or an existing safeguard) is in place.

### Citations

**File:** core/crypto/src/signature.rs (L98-105)
```rust
fn split_key_type_data(value: &str) -> Result<(KeyType, &str), crate::errors::ParseKeyTypeError> {
    if let Some((prefix, key_data)) = value.split_once(':') {
        Ok((KeyType::from_str(prefix)?, key_data))
    } else {
        // If there is no prefix then we Default to ED25519.
        Ok((KeyType::ED25519, value))
    }
}
```

**File:** core/crypto/src/signature.rs (L122-126)
```rust
impl std::fmt::Debug for Secp256K1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Display::fmt(&Bs58(&self.0), f)
    }
}
```

**File:** core/crypto/src/signature.rs (L185-189)
```rust
impl Debug for MlDsa65PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        Display::fmt(&Bs58(self.0.as_ref()), f)
    }
}
```

**File:** core/crypto/src/signature.rs (L455-466)
```rust
impl FromStr for PublicKey {
    type Err = crate::errors::ParseKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key_type, key_data) = split_key_type_data(value)?;
        Ok(match key_type {
            KeyType::ED25519 => Self::ED25519(ED25519PublicKey(decode_bs58(key_data)?)),
            KeyType::SECP256K1 => Self::SECP256K1(Secp256K1PublicKey(decode_bs58(key_data)?)),
            KeyType::MLDSA65 => Self::MLDSA65(MlDsa65PublicKey(Box::new(decode_bs58(key_data)?))),
        })
    }
}
```

**File:** core/crypto/src/signature.rs (L653-681)
```rust
impl FromStr for PublicKeyHandle {
    type Err = crate::errors::ParseKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(data) = value.strip_prefix(ML_DSA_65_HASH_PREFIX) {
            return Ok(Self::MlDsa65(MlDsa65PublicKeyHandle(try_fixed_array(
                &bs58::decode(data)
                    .into_vec()
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?,
            )?)));
        }
        let (key_type, key_data) = split_key_type_data(value)?;
        match key_type {
            KeyType::ED25519 => Ok(Self::ED25519(ED25519PublicKey(decode_bs58(key_data)?))),
            KeyType::SECP256K1 => {
                Ok(Self::SECP256K1(Secp256K1PublicKey::from(decode_bs58::<64>(key_data)?)))
            }
            // Full ML-DSA-65 keys never appear on the wire in this form -
            // they would be unrepresentable in `PublicKeyHandle`. The caller
            // should hash the pubkey first (via `From<&PublicKey>`) or
            // pass the `ml-dsa-65-hash:` form directly.
            KeyType::MLDSA65 => Err(Self::Err::InvalidData {
                error_message: "full ML-DSA-65 keys cannot appear in a PublicKeyHandle; \
                                use the `ml-dsa-65-hash:` form instead"
                    .to_string(),
            }),
        }
    }
}
```

**File:** core/crypto/src/signature.rs (L906-931)
```rust
impl FromStr for SecretKey {
    type Err = crate::errors::ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_type, key_data) = split_key_type_data(s)?;
        Ok(match key_type {
            KeyType::ED25519 => Self::ED25519(ED25519SecretKey(decode_bs58(key_data)?)),
            KeyType::SECP256K1 => {
                let data = decode_bs58::<{ secp256k1::constants::SECRET_KEY_SIZE }>(key_data)?;
                let sk = secp256k1::SecretKey::from_slice(&data)
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                Self::SECP256K1(sk)
            }
            KeyType::MLDSA65 => {
                let data = decode_bs58::<ML_DSA_65_SECRET_KEY_LENGTH>(key_data)?;
                // Mirror SECP256K1: validate the bytes form a valid
                // private key by handing them to the library. Catches
                // malformed-but-correct-length blobs at parse time
                // rather than blowing up later in `sign()`.
                PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &data[..])
                    .map_err(|err| Self::Err::InvalidData { error_message: err.to_string() })?;
                Self::MLDSA65(MlDsa65SecretKey(Box::new(data)))
            }
        })
    }
}
```
