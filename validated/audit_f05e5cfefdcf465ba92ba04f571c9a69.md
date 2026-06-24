Audit Report

## Title
`SenderInfoContent` Lacks Request-Context Binding, Enabling Cross-Canister Attestation Replay — (`rs/types/types/src/messages/http.rs`, `rs/validator/src/ingress_validation.rs`)

## Summary

`SenderInfoContent` signs only the raw `info` blob with no binding to `canister_id`, `sender`, or `ingress_expiry`. The validator `verify_sender_info_canister_sig` performs no certificate-timestamp check. Together these allow an attacker who has obtained any valid `sender_info.sig` to replay it verbatim against any target canister and across any number of fresh ingress messages, bypassing the access-control intent of the `sender_info` attestation mechanism.

## Finding Description

**Root cause 1 — Missing request-context binding in `SenderInfoContent`.**

`SenderInfoContent` is defined as a newtype over `&[u8]` and its `SignedBytesWithoutDomainSeparator` implementation writes only those bytes:

```rust
// rs/types/types/src/messages/http.rs L342-348
pub struct SenderInfoContent<'a>(pub &'a [u8]);

impl crate::crypto::SignedBytesWithoutDomainSeparator for SenderInfoContent<'_> {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0);   // only info bytes
    }
}
``` [1](#0-0) 

The full domain-separated signed bytes are therefore `\x0Eic-sender-info` + `info_bytes` with no `canister_id`, `sender`, or `ingress_expiry`. Any valid `(info_bytes, signer, sig)` triple is cryptographically valid for every target canister and every sender principal.

**Root cause 2 — No certificate-timestamp check in `verify_sender_info_canister_sig`.**

`verify_sender_info_canister_sig` checks only that the canister ID in `sender_pubkey` matches `sender_info.signer` and that the canister signature over `SenderInfoContent(&sender_info.info)` verifies against the root of trust:

```rust
// rs/validator/src/ingress_validation.rs L530-544
let sender_info_content = SenderInfoContent(&sender_info.info);
let canister_sig = CanisterSigOf::from(CanisterSig(sender_info.sig.clone()));
verify_canister_sig_with_fallback!(
    validator, &canister_sig, &sender_info_content, &public_key,
    root_of_trust_provider, ...
);
Ok(())
``` [2](#0-1) 

No certificate `time` field is extracted or compared against the current replica time. The outer `validate_ingress_expiry` check applies only to the ingress message's own `ingress_expiry`, not to the age of the canister-signature certificate embedded in `sender_info.sig`. [3](#0-2) 

**Why the envelope-level binding does not mitigate this.**

The `MessageId` representation-independent hash does include the full `sender_info` triple (`info`, `signer`, `sig`), so the envelope-level `sender_sig` is bound to a specific `sender_info.sig` value: [4](#0-3) 

However, this only prevents tampering with `sender_info.sig` after the fact. It does not prevent the attacker from constructing a *new* ingress message to a *different* canister that embeds the same `sender_info.sig` and signing that new message with their own key. The envelope signature is fresh and valid; only the inner canister signature is reused.

**Exploit flow — cross-canister replay:**

1. Attacker legitimately obtains a `sender_info.sig` over `info = b"role:admin"` targeting canister X (e.g., from their own prior request or from the signing canister directly).
2. Attacker constructs a new `HttpCanisterUpdate` targeting canister Y, embedding the same `sender_info.{info, signer, sig}`.
3. Attacker signs the new `MessageId` with their own key (fresh, valid envelope signature).
4. `validate_sender_info` passes: `sender_pubkey` encodes the signing canister ID, `pubkey_canister_id == sender_info.signer`, and `SenderInfoContent(b"role:admin")` verifies against the reused certificate. No `canister_id` check is performed.
5. Canister Y receives the attested `info` blob and grants elevated access.

**Exploit flow — stale attestation replay:**

1. Signing canister certifies `info = b"role:admin"` for user A at time T.
2. User A's attributes are revoked; the signing canister updates its certified data.
3. User A retains the old `sender_info.sig`. Because no certificate-timestamp check exists in `verify_sender_info_canister_sig`, the old certificate continues to pass verification.
4. User A submits new ingress messages (each with a fresh `ingress_expiry`) reusing the stale `sender_info.sig`; the revoked attributes are accepted indefinitely.

## Impact Explanation

Any canister that reads the `sender_info` blob and makes access-control decisions based on its contents is vulnerable to authentication bypass. An attacker can present revoked or cross-context attestations as valid. This maps to **High ($2,000–$10,000): Unauthorized access to canister-controlled resources where exploitation requires meaningful per-target work** — the attacker must first obtain a valid `sender_info.sig`, but once obtained, replay is trivial and repeatable across any number of target canisters and time windows.

## Likelihood Explanation

Medium-to-High. The `sender_info` feature is present in production validator code and has integration tests. Any canister using `sender_info` for access control is affected. The attacker needs only one prior valid `sender_info.sig` (obtainable from their own legitimate request). No special privileges, no social engineering, and no consensus-level access are required. The attack is repeatable with zero marginal cost per replay.

## Recommendation

1. **Bind `SenderInfoContent` to the request context.** Extend the struct to carry `canister_id` and `sender`, and include them in the signed bytes:

```rust
pub struct SenderInfoContent<'a> {
    pub canister_id: &'a CanisterId,
    pub sender: &'a UserId,
    pub info: &'a [u8],
}

impl crate::crypto::SignedBytesWithoutDomainSeparator for SenderInfoContent<'_> {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.canister_id.as_ref());
        bytes.extend_from_slice(self.sender.get_ref().as_slice());
        bytes.extend_from_slice(self.info);
    }
}
```

2. **Enforce a certificate-age deadline.** In `verify_sender_info_canister_sig`, extract the `time` field from the canister-signature certificate and reject it if `current_time - cert_time > MAX_INGRESS_TTL` (consistent with the existing ingress expiry window enforced by `validate_ingress_expiry`). [5](#0-4) 

## Proof of Concept

```
1. Call the signing canister (e.g., Internet Identity) to obtain a valid
   sender_info.sig over info = b"role:admin" for a request to canister X.

2. Construct HttpCanisterUpdate {
       canister_id: canister_Y,          // different target
       method_name: "privileged_action",
       sender: user_A,
       ingress_expiry: <fresh expiry>,
       sender_info: Some(SignedSenderInfo {
           info: b"role:admin",
           signer: II_canister_id,
           sig: <reused sig from step 1>,
       }),
   }

3. Sign the new MessageId with user_A's key (fresh envelope signature).

4. Submit to replica. validate_sender_info passes:
   - sender_pubkey encodes II_canister_id ✓
   - pubkey_canister_id == sender_info.signer ✓
   - SenderInfoContent(b"role:admin") verifies against reused certificate ✓
   - No canister_id or expiry check ✓

5. Canister Y's access-control logic receives b"role:admin" and grants
   elevated access that was never attested for canister Y.

Deterministic integration test: adapt rs/validator/ingress_message/tests/validate_request.rs
to construct two requests to different canisters sharing the same sender_info.sig
and assert both pass validate_request — demonstrating the missing binding.
``` [6](#0-5)

### Citations

**File:** rs/types/types/src/messages/http.rs (L342-348)
```rust
pub struct SenderInfoContent<'a>(pub &'a [u8]);

impl crate::crypto::SignedBytesWithoutDomainSeparator for SenderInfoContent<'_> {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0);
    }
}
```

**File:** rs/validator/src/ingress_validation.rs (L459-488)
```rust
fn validate_sender_info<C: HttpRequestContent, R: RootOfTrustProvider>(
    request: &HttpRequest<C>,
    ingress_signature_verifier: &dyn IngressSigVerifier,
    root_of_trust_provider: &R,
) -> Result<(), RequestValidationError>
where
    R::Error: std::error::Error,
{
    let Some(sender_info) = request.sender_info() else {
        return Ok(());
    };

    // Per the spec, the sender_info signature must verify using the
    // envelope-level sender_pubkey as a canister signature public key.
    let sender_pubkey = match request.authentication() {
        Authentication::Authenticated(sig) => &sig.signer_pubkey,
        Authentication::Anonymous => {
            return Err(InvalidSenderInfo(
                "sender_info requires an authenticated request with sender_pubkey".to_string(),
            ));
        }
    };

    verify_sender_info_canister_sig(
        sender_info,
        sender_pubkey,
        ingress_signature_verifier,
        root_of_trust_provider,
    )
}
```

**File:** rs/validator/src/ingress_validation.rs (L529-545)
```rust
    // Construct the signable content (domain = "ic-sender-info")
    let sender_info_content = SenderInfoContent(&sender_info.info);
    let canister_sig = CanisterSigOf::from(CanisterSig(sender_info.sig.clone()));

    verify_canister_sig_with_fallback!(
        validator,
        &canister_sig,
        &sender_info_content,
        &public_key,
        root_of_trust_provider,
        |e| InvalidSenderInfo(format!("signature verification failed: {e}")),
        |e: <R as RootOfTrustProvider>::Error| InvalidSenderInfo(format!(
            "failed to get root of trust: {e}"
        ))
    );
    Ok(())
}
```

**File:** rs/validator/src/ingress_validation.rs (L547-562)
```rust
// Check if ingress_expiry is within a proper range with respect to the given
// time, i.e., it is not expired yet and is not too far in the future.
fn validate_ingress_expiry<C: HttpRequestContent>(
    request: &HttpRequest<C>,
    current_time: Time,
) -> Result<(), RequestValidationError> {
    let ingress_expiry = request.ingress_expiry();
    let provided_expiry = Time::from_nanos_since_unix_epoch(ingress_expiry);
    let min_allowed_expiry = current_time;
    // We need to account for time drift and be more forgiving at rejecting ingress
    // messages due to their expiry being too far in the future.
    // If this logic changes, then the migration canister in `//rs/migration_canister`
    // must be updated, too.
    let max_expiry_diff = MAX_INGRESS_TTL
        .checked_add(PERMITTED_DRIFT_AT_VALIDATOR)
        .ok_or_else(|| {
```

**File:** rs/types/types/src/messages/ingress_messages.rs (L112-130)
```rust
impl HttpRequestContent for SignedIngressContent {
    fn id(&self) -> MessageId {
        MessageId::from(representation_independent_hash_call_or_query(
            CallOrQuery::Call,
            self.canister_id.as_ref(),
            &self.method_name,
            &self.arg,
            self.ingress_expiry,
            self.sender.get_ref().as_slice(),
            self.nonce.as_deref(),
            self.sender_info
                .as_ref()
                .map(|sender_info| RawSignedSenderInfoSlices {
                    info: &sender_info.info,
                    signer: sender_info.signer.as_ref(),
                    sig: &sender_info.sig,
                }),
        ))
    }
```

**File:** rs/validator/ingress_message/tests/validate_request.rs (L1-1)
```rust
use assert_matches::assert_matches;
```
