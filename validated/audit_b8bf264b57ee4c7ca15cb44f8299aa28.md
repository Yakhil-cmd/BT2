### Title
`BLS12381SHA256` Implements `frost_core::Ciphersuite` with `unimplemented!()` Hash Methods, Causing Runtime Panic on Standard Interface Calls — (File: `src/confidential_key_derivation/ciphersuite.rs`)

---

### Summary

`BLS12381SHA256` is a publicly exported type that satisfies the `frost_core::Ciphersuite` trait. Five required hash methods (`H1`, `H2`, `H3`, `H4`, `H5`) and one optional method (`HID`) are all implemented with `unimplemented!()`. Any call to these methods causes an immediate, unrecoverable process panic rather than a graceful protocol error, permanently denying signing or CKD to any honest party whose execution path reaches them.

---

### Finding Description

In `src/confidential_key_derivation/ciphersuite.rs`, `BLS12381SHA256` declares a full `frost_core::Ciphersuite` implementation at line 41, but six of its required methods unconditionally panic:

```rust
// lines 50-86
fn H1(m: &[u8]) -> ... { unimplemented!() }
fn H2(m: &[u8]) -> ... { unimplemented!() }
fn H3(m: &[u8]) -> ... { unimplemented!() }
fn H4(m: &[u8]) -> Self::HashOutput { unimplemented!() }
fn H5(_m: &[u8]) -> Self::HashOutput { unimplemented!() }
fn HID(m: &[u8]) -> Option<...> { unimplemented!() }
```

The inline comment at lines 39–40 acknowledges this: *"We are currently not using all the functionality. Therefore, I implemented only those that we use."* Only `HDKG` (line 75–79) is properly implemented.

The problem is structural: `BLS12381SHA256` is a public type that satisfies `frost_core::Ciphersuite`. The `frost_core` library's own signing round functions (`round1::commit`, `round2::sign`, `aggregate`) dispatch through these exact hash methods internally:

- `H3` — nonce generation in `round1::commit`
- `H1`, `H2`, `H4`, `H5` — binding factor and challenge computation in `round2::sign` / `aggregate`
- `HID` — identifier derivation in participant-set operations

Any caller — including the library's own future code or an integrating application — that passes `BLS12381SHA256` to a `frost_core` generic function will trigger a panic rather than receiving a typed `ProtocolError`. Unlike a returned `Err(...)`, a panic unwinds or aborts the process, bypassing all error-handling logic in the caller.

The `#[allow(unused)]` attributes on the `m` parameters (lines 50, 55, 60, 65, 70, 81) suppress compiler warnings but do not prevent the runtime panic.

---

### Impact Explanation

**High — Permanent denial of signing or CKD for honest parties under valid protocol inputs.**

When any honest participant's execution reaches `H1`–`H5` or `HID` on `BLS12381SHA256`, the process panics unconditionally. There is no way for the caller to catch or recover from this: `unimplemented!()` expands to `panic!`, which in a multi-party protocol context terminates that participant's process entirely. The signing or CKD session cannot complete, and the output is permanently lost for that round. Because `BLS12381SHA256` is the sole ciphersuite for the CKD subsystem, any future extension of the CKD protocol that invokes these standard hash methods — or any integrating application that uses `BLS12381SHA256` generically with `frost_core` — will hit this denial unconditionally.

---

### Likelihood Explanation

**Medium.** `BLS12381SHA256` is a public type that advertises a complete `frost_core::Ciphersuite` implementation. An integrating application or a future maintainer extending the CKD protocol has no compile-time signal that six of the trait's methods are traps. The `#[allow(unused)]` suppression hides even the lint warning. The trigger requires only a call to any `frost_core` generic function parameterized on `BLS12381SHA256` — a natural and expected usage given the trait bound.

---

### Recommendation

Replace each `unimplemented!()` body with a correct domain-separated hash implementation consistent with the BLS12-381 / SHA-256 ciphersuite, following the same pattern as `HDKG` and the existing `hash_to_scalar` helper. If certain methods are intentionally out of scope for the CKD use-case, return a typed error via a wrapper rather than panicking, or remove the `frost_core::Ciphersuite` impl entirely and expose only the subset of functionality that is actually supported.

---

### Proof of Concept

```rust
use threshold_signatures::confidential_key_derivation::ciphersuite::BLS12381SHA256;

// Any frost_core generic function that internally calls H1–H5 or HID will panic.
// For example, frost_core::round2::sign dispatches through H1, H2, H4, H5.
// The call below panics unconditionally with "not implemented":
let _ = frost_core::round1::commit::<BLS12381SHA256>(
    &signing_share,
    &mut rng,
); // → panic: "not implemented" (H3 called internally for nonce generation)
```

The root cause is at: [1](#0-0) 

Specifically the six `unimplemented!()` bodies: [2](#0-1) [3](#0-2) 

The only correctly implemented method is `HDKG`: [4](#0-3)

### Citations

**File:** src/confidential_key_derivation/ciphersuite.rs (L41-87)
```rust
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
