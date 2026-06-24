Audit Report

## Title
Unbounded Derivation Path Element Size Enables CPU Exhaustion in Synchronous Replicated Execution — (`rs/types/management_canister_types/src/lib.rs`, `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/key_derivation.rs`)

## Summary
The `DerivationPath` type alias bounds only the number of path elements (max 255) but leaves both per-element and total data size completely unbounded (`UNBOUNDED = usize::MAX`). An unprivileged canister can supply path elements up to the inter-canister payload limit, causing `bip32_ckd` / `eddsa_ckd` to feed that data into HMAC-SHA512 / HKDF-SHA512 in native Rust code that is not subject to Wasm instruction limits. Because `ECDSAPublicKey` is dispatched synchronously and returns `Finished` inline in the execution environment, this computation blocks the execution thread on every replica in the subnet before the block can advance.

## Finding Description

**Root cause — unbounded element size in `DerivationPath`:**

The type alias at line 3236 of `rs/types/management_canister_types/src/lib.rs` is:

```rust
pub type DerivationPath = BoundedVec<MAXIMUM_DERIVATION_PATH_LENGTH, UNBOUNDED, UNBOUNDED, ByteBuf>;
``` [1](#0-0) 

`UNBOUNDED` is `usize::MAX`: [2](#0-1) 

During deserialization, the element-count check at line 109 fires correctly, but the element-size check at line 116 (`new_element_data_size > MAX_ALLOWED_ELEMENT_DATA_SIZE`) and the total-size check at line 124 are never triggered because both constants equal `usize::MAX`: [3](#0-2) 

**Crypto layer — index bytes fed directly into HMAC/HKDF without size guard:**

In `bip32_ckd`, the full `index.0` byte slice is written into HMAC-SHA512 with no length check: [4](#0-3) 

In `eddsa_ckd`, the full `index.0` is appended to IKM and passed to HKDF-SHA512: [5](#0-4) 

The only guard in `derive_tweak_with_chain_code` is the path-length check; there is no check on `idx.0.len()`: [6](#0-5) 

**Execution layer — synchronous, native, no instruction accounting:**

`ECDSAPublicKey` is dispatched synchronously and returns `ExecuteSubnetMessageResult::Finished` immediately after the key derivation completes, meaning the native Rust HMAC computation runs inline on the execution thread with no Wasm instruction counter: [7](#0-6) 

**Benchmark confirms large elements are accepted and processed:**

The benchmark at lines 90–96 of `rs/execution_environment/benches/management_canister/ecdsa.rs` uses a single 2 MB element and expects `InvalidPoint` — a crypto error from an invalid test key — **not** a size-rejection error. This confirms the 2 MB element passes all validation and reaches the HMAC computation: [8](#0-7) 

Note on the claim's specific numbers: the assertion that 255 × 2 MB = 510 MB is achievable in a single call is overstated. The IC's inter-canister payload limit (~2 MB) constrains the total derivation path data per call. However, the vulnerability is real and exploitable within that limit: an attacker can use 255 elements × ~7,800 bytes ≈ 2 MB total, or a single ~2 MB element, both of which pass all validation and reach the HMAC computation as confirmed by the benchmark.

## Impact Explanation

This is a **High** severity finding matching the allowed impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS." A canister can repeatedly submit `ecdsa_public_key` calls with maximally-sized derivation paths. Each call runs native HMAC-SHA512 synchronously on the execution thread across all replicas in the subnet before the block advances. Sustained calls can delay block finalization and degrade subnet availability for all users on the subnet.

## Likelihood Explanation

The attack requires only a deployed canister with sufficient cycles to make inter-canister calls to the management canister. No privileged access, governance majority, or key material is needed. The missing bound is structural and has been present since the `BoundedVec` type was introduced. The benchmark code itself demonstrates that 2 MB path elements are a known test case, yet no rejection was added. The attack is repeatable and does not require victim interaction.

## Recommendation

Change the `DerivationPath` type alias to enforce a per-element size limit and a total-data-size cap:

```rust
const MAX_DERIVATION_PATH_ELEMENT_SIZE: usize = 255;
const MAX_DERIVATION_PATH_TOTAL_SIZE: usize = 255 * 255; // ~65 KB

pub type DerivationPath = BoundedVec<
    MAXIMUM_DERIVATION_PATH_LENGTH,
    MAX_DERIVATION_PATH_TOTAL_SIZE,
    MAX_DERIVATION_PATH_ELEMENT_SIZE,
    ByteBuf,
>;
```

Additionally, add an explicit `idx.0.len()` guard inside `bip32_ckd` and `eddsa_ckd` as defense-in-depth, returning `CanisterThresholdError::InvalidArguments` if the index exceeds the allowed size.

## Proof of Concept

The existing benchmark at `rs/execution_environment/benches/management_canister/ecdsa.rs:90–96` is itself a proof of concept: it submits a derivation path with a 2 MB element and receives `InvalidPoint` (a crypto error), not a size-rejection error, confirming the element reaches HMAC computation. A minimal integration test using `StateMachineBuilder` can reproduce this:

```rust
// Deploy a canister that calls ecdsa_public_key with:
// derivation_path = [vec![0u8; 7_800]; 255]  // ~2 MB total, within payload limit
// Each of 255 steps feeds ~7.8 KB into HMAC-SHA512 in native replica code.
// Repeated calls block the execution thread on all subnet replicas.
// Expected: call accepted (element count = 255 ≤ 255, total size ≤ 2 MB),
// derivation proceeds, returns InvalidPoint (crypto error, not size rejection).
``` [8](#0-7)

### Citations

**File:** rs/types/management_canister_types/src/lib.rs (L3236-3236)
```rust
pub type DerivationPath = BoundedVec<MAXIMUM_DERIVATION_PATH_LENGTH, UNBOUNDED, UNBOUNDED, ByteBuf>;
```

**File:** rs/types/management_canister_types/src/bounded_vec.rs (L6-7)
```rust
/// Indicates that `BoundedVec<...>` template parameter (eg. length, total data size, etc) is unbounded.
pub const UNBOUNDED: usize = usize::MAX;
```

**File:** rs/types/management_canister_types/src/bounded_vec.rs (L108-132)
```rust
                while let Some(element) = seq.next_element::<T>()? {
                    if elements.len() >= MAX_ALLOWED_LEN {
                        return Err(serde::de::Error::custom(format!(
                            "The number of elements exceeds maximum allowed {MAX_ALLOWED_LEN}"
                        )));
                    }
                    // Check that the new element data size is below the maximum allowed limit.
                    let new_element_data_size = element.data_size();
                    if new_element_data_size > MAX_ALLOWED_ELEMENT_DATA_SIZE {
                        return Err(serde::de::Error::custom(format!(
                            "The single element data size exceeds maximum allowed {MAX_ALLOWED_ELEMENT_DATA_SIZE}"
                        )));
                    }
                    // Check that the new total data size (including new element data size)
                    // is below the maximum allowed limit.
                    let new_total_data_size = total_data_size + new_element_data_size;
                    if new_total_data_size > MAX_ALLOWED_TOTAL_DATA_SIZE {
                        return Err(serde::de::Error::custom(format!(
                            "The total data size exceeds maximum allowed {MAX_ALLOWED_TOTAL_DATA_SIZE}"
                        )));
                    }
                    total_data_size = new_total_data_size;
                    elements.push(element);
                }
                Ok(BoundedVec::new(elements))
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/key_derivation.rs (L83-88)
```rust
        let mut hmac = Hmac::<Sha512>::new(chain_key);

        hmac.write(key_input);
        hmac.write(&index.0);

        let hmac_output = hmac.finish();
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/key_derivation.rs (L152-165)
```rust
        let mut ikm = public_key.serialize();
        ikm.extend_from_slice(&index.0);

        /*
        We derive the next additive offset and chain code using HKDF,
        using the parent chain key as the salt, the public key and
        index as the IKM (input key material) and the constant string
        "Ed25519" as the info/label field.
         */
        let info = "Ed25519".as_bytes();

        // Only way HKDF can fail is if output is too long, which can't
        // happen here.
        let okm = hkdf::<Sha512>(96, &ikm, chain_key, info).expect("HKDF failed unexpectedly");
```

**File:** rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/key_derivation.rs (L194-200)
```rust
        if self.len() > Self::MAXIMUM_DERIVATION_PATH_LENGTH {
            return Err(CanisterThresholdError::InvalidArguments(format!(
                "Derivation path len {} larger than allowed maximum of {}",
                self.len(),
                Self::MAXIMUM_DERIVATION_PATH_LENGTH
            )));
        }
```

**File:** rs/execution_environment/src/execution_environment.rs (L1339-1383)
```rust
            Ok(Ic00Method::ECDSAPublicKey) => {
                let cycles = msg.take_cycles();
                match &msg {
                    CanisterCall::Request(request) => {
                        let res = match ECDSAPublicKeyArgs::decode(request.method_payload()) {
                            Err(err) => Err(err),
                            Ok(args) => match get_master_public_key(
                                &chain_key_data.master_public_keys,
                                self.own_subnet_id,
                                &MasterPublicKeyId::Ecdsa(args.key_id.clone()),
                            ) {
                                Err(err) => Err(err),
                                Ok(pubkey) => {
                                    let canister_id = match args.canister_id {
                                        Some(id) => id.into(),
                                        None => *msg.sender(),
                                    };
                                    self.get_threshold_public_key(
                                        pubkey,
                                        canister_id,
                                        args.derivation_path.into_inner(),
                                    )
                                    .map(|res| {
                                        (
                                            ECDSAPublicKeyResponse {
                                                public_key: res.public_key,
                                                chain_code: res.chain_key,
                                            }
                                            .encode(),
                                            None,
                                        )
                                    })
                                }
                            },
                        };
                        ExecuteSubnetMessageResult::Finished {
                            response: res,
                            refund: cycles,
                        }
                    }
                    CanisterCall::Ingress(_) => {
                        self.reject_unexpected_ingress(Ic00Method::ECDSAPublicKey)
                    }
                }
            }
```

**File:** rs/execution_environment/benches/management_canister/ecdsa.rs (L90-96)
```rust
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:1/buf_size:2M",
        (10, 1, 2_000_000),
        |result| expect_error(result, ErrorCode::CanisterCalledTrap, "InvalidPoint"),
    );
```
