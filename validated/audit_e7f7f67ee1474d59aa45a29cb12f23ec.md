Audit Report

## Title
`SenderInfoContent` Lacks Expiry and Target-Canister Binding, Enabling Temporal and Cross-Canister Replay — (`rs/types/types/src/messages/http.rs`, `rs/validator/src/ingress_validation.rs`)

## Summary

`SenderInfoContent` signs only the raw `info` bytes under the domain separator `"ic-sender-info"`, with no target canister ID and no expiry timestamp bound into the signed message. Because IC canister signature certificates carry no protocol-enforced expiry and `verify_sender_info_canister_sig` performs no age or canister-binding check, a previously valid `sender_info` triple `{info, signer, sig}` can be replayed verbatim to any canister at any future time, even after the signing canister has revoked the underlying credential by updating its certified data.

## Finding Description

`SenderInfoContent` is defined as a bare wrapper over a byte slice:

```rust
// rs/types/types/src/messages/http.rs L341-348
pub struct SenderInfoContent<'a>(pub &'a [u8]);

impl crate::crypto::SignedBytesWithoutDomainSeparator for SenderInfoContent<'_> {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0);   // only raw info bytes
    }
}
```

Its `SignatureDomain` prepends only the fixed string `"ic-sender-info"`:

```rust
// rs/types/types/src/crypto/sign.rs L161-164
impl<'a> SignatureDomain for SenderInfoContent<'a> {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length("ic-sender-info")
    }
}
```

The resulting signed bytes are `\x0Eic-sender-info || info_bytes` — no target canister ID, no sender principal, no expiry.

`verify_sender_info_canister_sig` (rs/validator/src/ingress_validation.rs L494–544) performs exactly two checks:
1. The DER-encoded `sender_pubkey` is a valid canister signature public key.
2. The canister ID extracted from `sender_pubkey` matches `sender_info.signer`.

It then constructs `SenderInfoContent(&sender_info.info)` and verifies the canister signature against it — with no expiry enforcement and no canister-ID binding in the signed payload:

```rust
// rs/validator/src/ingress_validation.rs L529-543
let sender_info_content = SenderInfoContent(&sender_info.info);
let canister_sig = CanisterSigOf::from(CanisterSig(sender_info.sig.clone()));
verify_canister_sig_with_fallback!(
    validator, &canister_sig, &sender_info_content, &public_key,
    root_of_trust_provider, ...
);
```

`validate_sender_info` (L459–488) calls only `verify_sender_info_canister_sig`; no additional checks are applied. The outer `ingress_expiry` check (L117) applies to the HTTP envelope, not to the `sender_info` blob, so an attacker can embed the same old `sender_info` in a fresh envelope with a new `ingress_expiry`.

IC canister signatures embed a BLS-signed certificate snapshot. `verify_certificate` validates the BLS signature but does not reject certificates based on age. Once issued, a certificate remains cryptographically valid indefinitely.

**Exploit path:**
1. User obtains `{info: b"kyc=true", signer: II_canister_id, sig: <canister_sig>}` from Internet Identity.
2. User submits a request to canister C1; replica verifies `\x0Eic-sender-info || b"kyc=true"` and accepts. C1 grants access.
3. Internet Identity revokes the credential (updates certified data, removing the hash).
4. User constructs a new HTTP request to canister C2 (or C1 again) with a fresh `ingress_expiry`, embedding the **same** `sender_info` triple.
5. `verify_sender_info_canister_sig` reconstructs `SenderInfoContent(b"kyc=true")`, verifies the old certificate snapshot (still a valid BLS-signed certificate), and succeeds. C2 grants access based on a revoked credential.

The cross-canister variant is identical: the same triple works for any canister on any subnet because no canister ID appears in the signed content.

## Impact Explanation

Any canister that reads `sender_info` for attribute-based access control (KYC status, age verification, credential checks) accepts stale or revoked attestations indefinitely and accepts attestations originally issued for a different canister. This constitutes unauthorized access to canister-controlled resources or identity-gated functionality. This matches **High ($2,000–$10,000): Unauthorized access to identities, canister-controlled funds, or governance assets where exploitation requires meaningful per-target work or other constraints** — the constraint being prior possession of a once-valid `sender_info` blob, which is trivially retained by any user.

## Likelihood Explanation

The attacker is the legitimate user themselves. No cryptographic capability beyond retaining previously received HTTP response bytes is required. The `sender_info` feature is present in production replica code and is actively tested end-to-end. As dapps adopt `sender_info` for attribute-based access control (the stated purpose), the exploitable surface grows linearly with adoption. The attack is repeatable and requires no privileged access.

## Recommendation

1. **Bind the target canister ID**: Include the target canister ID in `SenderInfoContent` so a signature issued for canister A cannot be replayed to canister B.
2. **Bind an expiry**: Include an expiry timestamp (or tie it to the outer request's `ingress_expiry`) in `SenderInfoContent` and enforce it in `verify_sender_info_canister_sig`.
3. **Alternatively**, adopt the `Delegation` pattern (`Delegation` already carries `expiration` and `targets`) so the same replay-protection machinery applies to `sender_info`.

The minimal fix is to extend `SenderInfoContent` to carry `(info_bytes, target_canister_id, expiry_ns)`, update `verify_sender_info_canister_sig` to enforce the expiry against `current_time` and verify the canister-ID match, and update the signing canister (Internet Identity) accordingly.

## Proof of Concept

A deterministic integration test using PocketIC or the state machine test framework:

1. Deploy a signing canister S and a target canister T1 and T2.
2. Have S issue a canister signature over `\x0Eic-sender-info || b"attr=true"` and return `{info, signer, sig}`.
3. Submit a call to T1 with this `sender_info`; assert it is accepted.
4. Have S update its certified data to remove the hash (simulating revocation).
5. Advance the replica clock past the original certificate time.
6. Submit a **new** call to T2 (different canister) with the **same** `sender_info` and a fresh `ingress_expiry`; assert it is still accepted — demonstrating both temporal and cross-canister replay.