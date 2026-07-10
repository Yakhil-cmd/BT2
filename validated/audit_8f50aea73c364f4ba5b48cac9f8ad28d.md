### Title
`BLS12381SHA256` Ciphersuite is Not Fully `frost_core::Ciphersuite` Compliant, Causing Runtime Panics on FROST Signing Paths — (`src/confidential_key_derivation/ciphersuite.rs`)

---

### Summary

`BLS12381SHA256` is declared as implementing `crate::Ciphersuite` (which extends `frost_core::Ciphersuite`), but six of the eight required hash functions — `H1`, `H2`, `H3`, `H4`, `H5`, and `HID` — are left as `unimplemented!()`. Because `BLS12381SHA256` satisfies the `Ciphersuite` trait bound at the type level, it can be passed to any generic function accepting `C: Ciphersuite`, including the FROST presign and sign protocols. Any such call will panic at runtime, permanently denying signing for honest parties.

---

### Finding Description

In `src/confidential_key_derivation/ciphersuite.rs`, the `BLS12381SHA256` struct implements `frost_core::Ciphersuite` with the following stubs:

```rust
// We are currently not using all the functionality. Therefore,
// I implemented only those that we use.
impl frost_core::Ciphersuite for BLS12381SHA256 {
    fn H1(m: &[u8]) -> ... { unimplemented!() }
    fn H2(m: &[u8]) -> ... { unimplemented!() }
    fn H3(m: &[u8]) -> ... { unimplemented!() }
    fn H4(m: &[u8]) -> Self::HashOutput { unimplemented!() }
    fn H5(_m: &[u8]) -> Self::HashOutput { unimplemented!() }
    fn HID(m: &[u8]) -> Option<...> { unimplemented!() }
    fn HDKG(m: &[u8]) -> Option<...> { Some(hash_to_scalar(...)) } // only this is real
}
``` [1](#0-0) 

The blanket impl `impl crate::Ciphersuite for BLS12381SHA256 {}` makes this type satisfy the `crate::Ciphersuite` bound used throughout the library. [2](#0-1) 

The FROST presign function in `src/frost/mod.rs` is generic over `C: Ciphersuite` and calls `frost_core::round1::commit`, which internally invokes `H3` for nonce generation:

```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
``` [3](#0-2) 

Inside `do_presign`, `commit(&signing_share, &mut rng)` is called, which in `frost_core` uses `H3` for nonce derivation: [4](#0-3) 

Similarly, the FROST sign functions in `src/frost/eddsa/sign.rs` and `src/frost/redjubjub/sign.rs` call `frost_core::round2::sign`, which uses `H1` and `H2` to compute the binding factor and challenge. All of these will panic if `BLS12381SHA256` is supplied.

The DKG path (`src/dkg.rs`) only calls `C::HDKG` (line 109) and the default `generate_nonce` (which uses only the RNG, not `H3`), so DKG itself is safe. The panic surface is exclusively the FROST presign/sign path. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

Any caller who invokes `presign::<BLS12381SHA256>(...)` or any FROST sign function with `BLS12381SHA256` will receive an unconditional `panic!` at runtime. Because `BLS12381SHA256` satisfies the `Ciphersuite` trait bound at compile time, the compiler provides no warning. The result is **permanent denial of signing** for any honest party that attempts to use this ciphersuite with the FROST signing path — matching the allowed High impact: *"Permanent denial of signing … for honest parties under valid protocol inputs and documented trust assumptions."*

---

### Likelihood Explanation

`BLS12381SHA256` is a publicly exported type that satisfies `crate::Ciphersuite`. The `presign` and sign functions are generic over `C: Ciphersuite`. A library integrator building a CKD-based system who attempts to reuse the same ciphersuite type for FROST signing (a natural assumption given the unified `Ciphersuite` trait) will trigger the panic. The only in-code hint is a comment ("We are currently not using all the functionality"), which is not surfaced in the public API documentation.

---

### Recommendation

1. **Remove the `frost_core::Ciphersuite` impl for `BLS12381SHA256`** and replace it with a narrower, CKD-specific trait that only requires `HDKG`. This prevents the type from being passed to FROST signing functions at compile time.
2. **Alternatively**, implement all required hash functions (`H1`–`H5`, `HID`) correctly for `BLS12381SHA256` so the type is genuinely compliant with `frost_core::Ciphersuite`.
3. If option 1 is chosen, introduce a separate sealed trait (e.g., `CKDCiphersuite`) that `BLS12381SHA256` implements, and restrict CKD-specific functions to `C: CKDCiphersuite` rather than `C: Ciphersuite`.

---

### Proof of Concept

```rust
use threshold_signatures::confidential_key_derivation::ciphersuite::BLS12381SHA256;
use threshold_signatures::frost::presign;
// BLS12381SHA256 satisfies C: Ciphersuite — compiles fine.
// At runtime, frost_core::round1::commit calls H3 → unimplemented!() → panic.
let _ = presign::<BLS12381SHA256>(&participants, me, &args, rng);
// thread 'main' panicked at 'not implemented'
```

The root cause is at: [7](#0-6) 

triggered via: [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/ciphersuite.rs (L35-35)
```rust
impl crate::Ciphersuite for BLS12381SHA256 {}
```

**File:** src/confidential_key_derivation/ciphersuite.rs (L39-87)
```rust
// We are currently not using all the functionality. Therefore,
// I implemented only those that we use.
impl frost_core::Ciphersuite for BLS12381SHA256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = BLS12381G2Group;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    #[allow(unused)]
    fn H1(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H2(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H3(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H4(m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    #[allow(unused)]
    fn H5(_m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    fn HDKG(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m))
    }

    #[allow(unused)]
    fn HID(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        unimplemented!()
    }
}
```

**File:** src/frost/mod.rs (L44-88)
```rust
pub fn presign<C>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments<C>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput<C>>, InitializationError>
where
    C: Ciphersuite + Send,
    <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar: Send,
    <<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Element: std::marker::Send,
{
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.into(),
            max: participants.len(),
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args.keygen_out.private_share,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/frost/mod.rs (L101-101)
```rust
    let (nonces, commitments) = commit(&signing_share, &mut rng);
```

**File:** src/dkg.rs (L109-109)
```rust
    let hash = C::HDKG(&preimage[..]).ok_or(ProtocolError::DKGNotSupported)?;
```

**File:** src/dkg.rs (L132-132)
```rust
    let (k, big_r) = <C>::generate_nonce(rng);
```
