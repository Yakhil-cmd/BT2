### Title
Forward/Proving Divergence Risk from Dual Field-Element Representations in Custom `secp256k1` Implementation — (`File: crypto/src/secp256k1/field/mod.rs`)

---

### Summary

ZKsync OS's custom `secp256k1` implementation selects entirely different internal field-element and scalar arithmetic types at compile time depending on the target architecture. The forward (sequencer, x86-64) execution path uses `FieldElement5x52` + `scalar64`, while the proving (RISC-V 32-bit, `bigint_ops` feature) path uses `FieldElement8x32` for runtime computation alongside `FieldElement10x26` for precomputed static-context constants. This mixed-representation scenario in proving mode — where the static generator-multiplication table is stored in one representation (`FieldElement10x26`) and consumed by a different one (`FieldElement8x32`) — is a structural analog to the eciesjs major-version mismatch: two components of the same logical operation use different internal implementations, creating a risk of subtle divergence between forward execution and proof generation for the `ecrecover` precompile.

---

### Finding Description

`crypto/src/secp256k1/field/mod.rs` selects field-element implementations via a `cfg_if!` block: [1](#0-0) 

- **64-bit forward mode** (`target_pointer_width = "64"`): both `FieldElementImpl` and `FieldElementImplConst` resolve to `FieldElement5x52` (5 limbs × 52 bits, 64-bit native arithmetic).
- **RISC-V proving mode** (`feature = "bigint_ops"`): `FieldElementImpl` resolves to `FieldElement8x32` (8 limbs × 32 bits, CSR-delegated arithmetic), while `FieldElementImplConst` and `FieldStorageImpl` resolve to `FieldElement10x26` (10 limbs × 26 bits, pure 32-bit arithmetic).

The scalar layer mirrors this split: [2](#0-1) 

- Forward: `scalar64` (64-bit native).
- Proving: `scalar32_delegation` (32-bit with CSR bigint delegation).

The static `ECRECOVER_CONTEXT` (precomputed generator multiplication table) is built using `FieldStorageImpl = FieldStorage10x26` in proving mode, but the runtime `ecmult` computation consumes `FieldElementImpl = FieldElement8x32`. A conversion between these two representations must occur at every table lookup. The README for this module explicitly acknowledges the dual-mode design: [3](#0-2) 

The `ecrecover_inner` function in `basic_system/src/system_functions/ecrecover.rs` calls `crypto::secp256k1::recover`, which dispatches through this architecture-dependent stack: [4](#0-3) 

The `recover_with_context` function in `crypto/src/secp256k1/recover.rs` performs the full `ecmult` using the static context: [5](#0-4) 

Any normalization invariant difference, carry-handling discrepancy, or conversion error between `FieldElement10x26` (constants) and `FieldElement8x32` (computation) in proving mode — that does not exist in the uniform `FieldElement5x52` path used in forward mode — would cause the two execution paths to produce different `ecrecover` outputs for the same input.

---

### Impact Explanation

**Vulnerability class:** Forward/proving divergence (EVM semantic mismatch between sequencer and prover).

If the `FieldElement10x26` → `FieldElement8x32` conversion or the `scalar32_delegation` arithmetic diverges from `FieldElement5x52` / `scalar64` for any input:

1. The sequencer (forward mode) computes and commits to a state root that includes the result of `ecrecover` for a given transaction.
2. The prover (proving mode) computes a different `ecrecover` result for the same transaction.
3. The prover cannot generate a valid proof for the sequencer's committed state, making the block **unprovable** — a liveness failure.
4. Alternatively, if the prover's result is accepted as authoritative, an incorrect address recovery could allow an attacker to craft a transaction whose `ecrecover` result differs between modes, potentially bypassing signature-based access controls in contracts that rely on `ecrecover` (e.g., EIP-712 permit flows, multisig wallets).

The `ecrecover` precompile is at address `0x0000000000000000000000000000000000000001` and is callable by any unprivileged transaction sender. [6](#0-5) 

---

### Likelihood Explanation

**Medium.** The dual-representation design is intentional and the team has a differential fuzzer (`tests/fuzzer/fuzz/fuzz_targets/precompiles_diff/ecrecover.rs`) that compares forward vs. proving outputs: [7](#0-6) 

The existence of this fuzzer confirms the team is aware of the divergence risk. However, fuzz coverage of a 256-bit input space is inherently incomplete. The mixed-representation scenario (`FieldElement10x26` constants + `FieldElement8x32` computation) is unique to proving mode and has no counterpart in the 64-bit path, meaning any bug in the conversion or in the interaction between the two types would be invisible to tests run only on x86. The `bigint_ops` delegation path also relies on CSR instructions (`csrrw x0, 0x7ca, x0`) whose correctness depends on the RISC-V circuit implementation: [8](#0-7) 

---

### Recommendation

1. **Add a compile-time or runtime equivalence assertion** that, for a representative set of test vectors, runs both the `FieldElement5x52`/`scalar64` path and the `FieldElement8x32`/`scalar32_delegation` path and asserts identical outputs. This should be part of CI and run on both x86 and RISC-V targets.
2. **Audit the `FieldElement10x26` → `FieldElement8x32` conversion** used when loading precomputed context points into runtime computation, verifying that normalization invariants are preserved across the boundary.
3. **Extend the differential fuzzer** (`precompiles_diff/ecrecover.rs`) to also run the proving-mode path natively on x86 (using the `proving` + `fuzzing` feature flags already present in `field/mod.rs`) to maximize coverage of the mixed-representation code path.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Deploy or interact with any contract that calls `ecrecover` (precompile address `0x1`) with a crafted 128-byte input `(digest, v, r, s)`.
2. The sequencer processes the block in forward mode (x86, `FieldElement5x52` + `scalar64`) and commits a state root reflecting the recovered address `A`.
3. The prover processes the same block in proving mode (RISC-V, `FieldElement8x32` + `scalar32_delegation` + `FieldElement10x26` context) and recovers address `B ≠ A` due to a normalization or conversion discrepancy.
4. The prover cannot produce a valid proof for the committed state root → block is unprovable → liveness failure.

**Structural root cause (file references):**

- Mixed-representation selection: `crypto/src/secp256k1/field/mod.rs:25–37`
- Mixed scalar selection: `crypto/src/secp256k1/scalars/mod.rs:21–29`
- Static context consumed by runtime computation: `crypto/src/secp256k1/recover.rs:30–73`
- Precompile dispatch: `basic_system/src/system_functions/ecrecover.rs:88–115`
- CSR delegation (proving-only arithmetic): `crypto/src/bigint_delegation/delegation.rs:63–92`

### Citations

**File:** crypto/src/secp256k1/field/mod.rs (L25-37)
```rust
cfg_if! {
    if #[cfg(all(debug_assertions, not(feature = "bigint_ops")))] {
        use field_impl::{FieldElementImpl as FieldElementImplConst, FieldElementImpl, FieldStorageImpl};
    } else if #[cfg(feature = "bigint_ops")] {
        use field_10x26::{FieldElement10x26 as FieldElementImplConst, FieldStorage10x26 as FieldStorageImpl};
        use field_8x32::FieldElement8x32 as FieldElementImpl;
    } else if #[cfg(target_pointer_width = "64")] {
        use field_5x52::{FieldElement5x52 as FieldElementImpl, FieldElement5x52 as FieldElementImplConst, FieldStorage5x52 as FieldStorageImpl};
    } else if #[cfg(target_pointer_width = "32")] {
        use field_10x26::{FieldElement10x26 as FieldElementImplConst, FieldElement10x26 as FieldElementImpl, FieldStorage10x26 as FieldStorageImpl};
    } else {
        panic!("unsupported arch");
    }
```

**File:** crypto/src/secp256k1/scalars/mod.rs (L21-29)
```rust
cfg_if! {
    if #[cfg(feature = "bigint_ops")] {
        use scalar32_delegation::ScalarInner;
    } else if #[cfg(target_pointer_width = "32")] {
        use scalar32::ScalarInner;
    } else if #[cfg(target_pointer_width = "64")] {
        use scalar64::ScalarInner;
    }
}
```

**File:** crypto/src/secp256k1/README.md (L1-4)
```markdown
# secp256k1
A highly optimised implementation of ecrecover precompile with precomputed generator multiplication table (i.e. static context). It can run in two modes - native 64-bit and 32-bit with delegation calls for u256 arithmatic. 

The basic structure is based on the implementation found in [k256](https://github.com/RustCrypto/elliptic-curves/tree/master/k256), with optimisations and static context added from [libsecp256k1](https://github.com/bitcoin-core/secp256k1). Both are acknowledged in the source code where applicable.
```

**File:** basic_system/src/system_functions/ecrecover.rs (L88-115)
```rust
pub fn ecrecover_inner(
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    rec_id: u8,
) -> Result<crypto::k256::EncodedPoint, ()> {
    use crypto::k256::{
        ecdsa::{hazmat::bits2field, RecoveryId, Signature},
        elliptic_curve::ops::Reduce,
        Scalar,
    };

    let signature = Signature::from_scalars(*r, *s).map_err(|_| ())?;
    let recovery_id = RecoveryId::try_from(rec_id).map_err(|_| ())?;

    let message = <Scalar as Reduce<crypto::k256::U256>>::reduce_bytes(
        &bits2field::<crypto::k256::Secp256k1>(digest).map_err(|_| ())?,
    );

    let Ok(pk) = crypto::secp256k1::recover(&message, &signature, &recovery_id) else {
        return Err(());
    };

    // represent as bytes, and we do not need compression
    let encoded = pk.to_encoded_point(false);

    Ok(encoded)
}
```

**File:** crypto/src/secp256k1/recover.rs (L30-73)
```rust
pub fn recover_with_context(
    message: &crate::k256::Scalar,
    signature: &crate::k256::ecdsa::Signature,
    recovery_id: &crate::k256::ecdsa::RecoveryId,
    context: &ECMultContext,
) -> Result<Affine, Secp256k1Err> {
    let (mut sigr, mut sigs) = Scalar::from_signature(signature);
    let message = Scalar::from_k256_scalar(*message);

    // We go through bytes because it's mod GROUP_ORDER and later we need mod BASE FIELD
    let mut brx = sigr.to_repr();

    if recovery_id.is_x_reduced() {
        match <U256 as FieldBytesEncoding<Secp256k1>>::decode_field_bytes(&brx)
            .checked_add(&Secp256k1::ORDER)
            .into_option()
        {
            Some(restored) => {
                brx = <U256 as FieldBytesEncoding<Secp256k1>>::encode_field_bytes(&restored);
            }
            None => return Err(Secp256k1Err::OperationOverflow),
        }
    }

    let is_odd = recovery_id.is_y_odd();
    let x = Affine::decompress(&brx, is_odd).ok_or(Secp256k1Err::InvalidParams)?;

    let xj = x.to_jacobian();

    sigr.invert_in_place();
    sigs *= sigr;

    sigr *= message;
    sigr.negate_in_place();

    let mut pk = ecmult(&xj, &sigs, &sigr, context).to_affine();
    pk.normalize_in_place();

    if pk.is_infinity() {
        return Err(Secp256k1Err::RecoveredInfinity);
    }

    Ok(pk)
}
```

**File:** system_hooks/src/lib.rs (L131-136)
```rust
    add_precompile::<
        _,
        _,
        <S::SystemFunctions as SystemFunctions<_>>::Secp256k1ECRecover,
        Secp256k1ECRecoverErrors,
    >(hooks, ECRECOVER_HOOK_ADDRESS_LOW)?;
```

**File:** tests/fuzzer/fuzz/fuzz_targets/precompiles_diff/ecrecover.rs (L1-31)
```rust
#![no_main]
#![feature(allocator_api)]

use arbitrary::{Arbitrary,Unstructured};
use libfuzzer_sys::fuzz_target;
use revm_precompile::secp256k1::ec_recover_run;
use fuzz_precompiles_forward::precompiles::ecrecover as ecrecover_forward;
use fuzz_precompiles_proving::precompiles::ecrecover as ecrecover_proving;
use secp256k1::{ecdsa::RecoverableSignature,Message,Secp256k1,SecretKey};
use crate::common::{be_inc_inplace,be_dec_inplace};

mod common;

const IN_LEN: usize = 128;

const N_SECP256K1: [u8; 32] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
];

const N_SECP256K1_HALF: [u8; 32] = [
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0,
];

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Case {
```

**File:** crypto/src/bigint_delegation/delegation.rs (L63-92)
```rust
#[cfg(all(target_arch = "riscv32", feature = "bigint_ops"))]
#[inline(always)]
pub(crate) fn bigint_op_delegation_with_carry_bit(
    a: *mut U256,
    b: *const U256,
    carry: bool,
    op: BigIntOps,
) -> u32 {
    debug_assert!(a.cast_const() != b);

    let a_adrr = a.addr();
    let b_adrr = b.addr();

    debug_assert!(a_adrr % 32 == 0);
    debug_assert!(b_adrr % 32 == 0);

    let mut mask = (1u32 << (op as usize)) | ((carry as u32) << CARRY_BIT_IDX);

    unsafe {
        core::arch::asm!(
            "csrrw x0, 0x7ca, x0",
            in("x10") a_adrr,
            in("x11") b_adrr,
            inlateout("x12") mask,
            options(nostack, preserves_flags)
        )
    }

    mask
}
```
