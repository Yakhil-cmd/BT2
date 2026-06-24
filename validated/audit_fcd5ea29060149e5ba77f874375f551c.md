Audit Report

## Title
Authentication Bypass via Non-Canonical Ed25519 Identity Element Encodings in Ingress Signature Verification — (`rs/crypto/standalone-sig-verifier/src/lib.rs`, `packages/ic-ed25519/src/lib.rs`)

## Summary

The ingress signature verification path accepts the three non-canonical encodings of the Ed25519 identity element as valid public keys and, under the ZIP215 verification rules implemented in `ic_ed25519::PublicKey::verify_signature`, any signature `(R=S*G, S)` verifies against the identity element as public key. An unprivileged attacker can forge a valid ingress message for the `PrincipalId` derived from any of these three encodings without possessing a private key.

## Finding Description

**Root cause — `deserialize_raw` accepts non-canonical identity encodings without canonicality check:**

`ic_ed25519::PublicKey::deserialize_raw` at `packages/ic-ed25519/src/lib.rs` L619–631 calls only `VerifyingKey::from_bytes`, which succeeds for all three non-canonical identity encodings. The function's own doc comment warns it does not check canonicality. The test at `packages/ic-ed25519/tests/tests.rs` L499–514 explicitly confirms all three encodings deserialize successfully, pass `is_torsion_free()`, and fail `is_canonical()`.

**Ingress path never calls `verify_public_key` or any canonicality check:**

`verify_public_key` in `rs/crypto/internal/crypto_lib/basic_sig/ed25519/src/api.rs` L97–103 is the only function that calls `is_torsion_free()`, but a `grep_search` across all `.rs` files confirms it is referenced only in its own definition and two test files — never in the ingress path. The actual ingress path is:

`validate_user_id_and_signature` (L841–877) → `validate_signature` (L635–703) → `validate_signature_plain` (L705–714) → `validator.verify_basic_sig_by_public_key` → `ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key` (L11–44)

That last function calls only `PublicKey::deserialize_raw` followed by `pk.verify_signature`. No canonicality or identity-element check is present anywhere in this chain.

**ZIP215 `verify_signature` accepts any `(R, S)` with `R = S·G` when the public key is the identity:**

`packages/ic-ed25519/src/lib.rs` L709–727 computes `recomputed_r = k·(−A) + S·G`. When `A` is the identity element, `−A` is also the identity, so `recomputed_r = S·G`. The check `(recomputed_r − R).mul_by_cofactor().is_identity()` passes whenever `R ≡ S·G (mod cofactor)`. Setting `S = 0` gives `R = identity` (canonical encoding `0x0100...00`), and the check trivially passes.

**Sender principal check is satisfied deterministically:**

`validate_user_id` at `rs/validator/src/ingress_validation.rs` L626–632 only requires `sender == PrincipalId::new_self_authenticating(sender_pubkey_der)`. The attacker computes this deterministically from the DER-wrapped non-canonical identity key and sets the `sender` field accordingly — no secret material needed.

**Contrast with the threshold library, which correctly rejects these encodings:**

`rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/utils/group/ed25519.rs` L295–348 defines `NON_CANONICAL_IDENTITIES` and explicitly returns `None` from `Point::deserialize` for any of the three encodings before any further processing. The ingress path has no equivalent guard.

## Impact Explanation

An attacker can fully impersonate the `PrincipalId` derived from any of the three non-canonical identity element encodings. Any ICP balance, cycles wallet, canister ownership, or other on-chain asset or privilege held by that principal can be accessed or transferred without authorization. This constitutes unauthorized access to identities and potentially ledger/canister-controlled funds, matching the **High** impact class: unauthorized access to wallets, identities, or canister-controlled funds.

## Likelihood Explanation

The attack requires no privileged access, no key material, no network position, and no victim interaction. The three target encodings are publicly documented. The forged signature `(R=canonical_identity, S=0)` is trivially constructable. The attack is fully deterministic and repeatable by any external user.

## Recommendation

In `ic_crypto_standalone_sig_verifier::verify_basic_sig_by_public_key` (`rs/crypto/standalone-sig-verifier/src/lib.rs`), after the `deserialize_raw` call for `AlgorithmId::Ed25519`, add an explicit check rejecting non-canonical encodings — either by calling `pk.is_canonical()` and returning `CryptoError::MalformedPublicKey` if false, or by checking the raw bytes against the three known `NON_CANONICAL_IDENTITIES` before deserialization, mirroring the pattern already used in the threshold signature library. Optionally, `ic_ed25519::PublicKey::deserialize_raw` itself could be hardened to reject non-canonical encodings by default, with a separate `deserialize_raw_unchecked` for callers that explicitly need ZIP215 permissiveness.

## Proof of Concept

```
# Choose any of the 3 non-canonical identity encodings as the raw public key:
non_canonical_pk_raw = 0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f  # 32 bytes

# DER-wrap it (standard Ed25519 DER prefix || raw key):
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
sender_pubkey_der = DER_PREFIX + non_canonical_pk_raw

# Derive the sender principal deterministically:
sender = PrincipalId::new_self_authenticating(sender_pubkey_der)

# Forge signature: S=0, R=canonical identity element
R = 0x0100000000000000000000000000000000000000000000000000000000000000  # 32 bytes
S = 0x0000000000000000000000000000000000000000000000000000000000000000  # 32 bytes
forged_sig = R || S  # 64 bytes

# Submit ingress message:
#   sender        = derived principal above
#   sender_pubkey = sender_pubkey_der
#   sender_sig    = forged_sig
#
# validate_user_id passes  (sender matches pubkey hash)
# deserialize_raw succeeds (non-canonical identity accepted)
# verify_signature passes  (S·G − R = identity − identity = 0; cofactor·0 = identity)
# → ingress accepted, attacker authenticated as that principal
```

A deterministic integration test can be written against a local replica or PocketIC by constructing the above ingress envelope and asserting it is accepted by the ingress validator.