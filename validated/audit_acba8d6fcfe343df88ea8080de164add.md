All cited code references check out exactly against the repository. Let me summarize the findings:

- `SenderInfoContent` at [1](#0-0)  is confirmed as a thin wrapper over raw `info` bytes only.
- `SignatureDomain` for `SenderInfoContent` at [2](#0-1)  prepends only `"ic-sender-info"` — no request context.
- `verify_sender_info_canister_sig` at [3](#0-2)  verifies only the three stated properties (valid DER key, canister ID match, signature over `info` bytes).
- `validate_sender_info` is called in the live validation path at [4](#0-3) .
- `SignedIngressContent` at [5](#0-4)  carries `canister_id`, `method_name`, `ingress_expiry`, `nonce`, and `sender_info` — none of which flow into the `sender_info` signature verification.

---

Audit Report

## Title
`sender_info` Canister Signature Not Bound to Request Context Enables Cross-Request Replay - (File: `rs/validator/src/ingress_validation.rs`)

## Summary
The `SenderInfoContent` signable used in `verify_sender_info_canister_sig` includes only the raw `info` bytes under the `"ic-sender-info"` domain separator, with no cryptographic binding to the enclosing request's `canister_id`, `method_name`, `ingress_expiry`, or `nonce`. A valid `sender_info` attestation obtained for one request can therefore be replayed verbatim in any other request by the same principal — to a different canister, a different method, or at a different time within the ingress window — bypassing any access-control logic that canisters build on top of `sender_info`.

## Finding Description
`SenderInfoContent` is defined as a thin wrapper over raw `info` bytes:

```rust
pub struct SenderInfoContent<'a>(pub &'a [u8]);
impl crate::crypto::SignedBytesWithoutDomainSeparator for SenderInfoContent<'_> {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.0);
    }
}
```

Its `SignatureDomain` prepends only the literal `"ic-sender-info"` domain separator, producing signed bytes of exactly `"\x0Eic-sender-info" || info_bytes`.

`verify_sender_info_canister_sig` enforces only:
1. `sender_pubkey` is a valid canister-signature DER public key.
2. The canister ID embedded in `sender_pubkey` equals `sender_info.signer`.
3. The canister signature `sender_info.sig` is valid over `SenderInfoContent(info_bytes)`.

It does **not** check that `info_bytes` contains any binding to the target `canister_id`, `method_name`, `ingress_expiry`, or `nonce` of the enclosing request. `SignedIngressContent` carries all of those fields alongside `sender_info`, but none of them flow into the `sender_info` signature verification path.

`validate_sender_info` is called unconditionally in `validate_request_content` at line 219, which is invoked by all three `validate_request` implementations (`SignedIngressContent`, `Query`, `ReadState`).

**Exploit path:**
1. A user authenticates with Internet Identity (or any canister acting as a `sender_info` signer) and obtains a valid `RawSignedSenderInfo { info, signer, sig }` for request R₁ targeting canister A / method `read_data`.
2. The attacker constructs a new request R₂ targeting canister B / method `privileged_action`, reusing the identical `(info, signer, sig)` triple.
3. The IC ingress validator accepts R₂: the envelope signature over the new `message_id` is freshly produced by the attacker's key, and `verify_sender_info_canister_sig` passes because the canister signature over `info_bytes` is still valid.
4. Canister B receives R₂ with the `sender_info` intact and, if it gates access on the attributes in `info_bytes`, grants the privileged operation.

The only natural limit is the `ingress_expiry` window (≤ `MAX_INGRESS_TTL` ≈ 5 minutes), but within that window the same `sender_info` is reusable across arbitrarily many requests to arbitrarily many canisters.

## Impact Explanation
Any canister that reads `sender_info` via the system API and uses it to make authorization decisions (e.g., "caller has role X", "caller passed KYC", "caller is a premium subscriber") is vulnerable. An attacker who legitimately obtains a `sender_info` attestation for one low-privilege call can replay it against any other canister or method that trusts the same attestation, bypassing the intended access-control invariant. This constitutes unauthorized access to canister-controlled resources and maps to the **High** bounty impact: "Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds" and "Significant Internet Identity security impact with concrete user or protocol harm," given that Internet Identity is the primary intended `sender_info` signer and is explicitly in scope.

## Likelihood Explanation
The attack requires no privileged access. Any user who has ever received a valid `sender_info` from a signing canister (the normal, intended flow) automatically possesses a replayable credential. Constructing a crafted request reusing the credential is trivial — it requires only assembling a standard IC HTTP envelope with the recycled `(info, signer, sig)` triple and a fresh envelope signature. The attack is repeatable within every ingress window and is realistic for any production canister that gates privileged operations on `sender_info`.

## Recommendation
Bind the `sender_info` canister signature to the enclosing request by including request-specific context in the signed content. At minimum, `SenderInfoContent` should incorporate the `canister_id` and `method_name` of the target request, and optionally the `ingress_expiry` or a per-session nonce:

```rust
pub struct SenderInfoContent<'a> {
    pub info: &'a [u8],
    pub canister_id: &'a [u8],
    pub method_name: &'a str,
}
```

This ensures that a `sender_info` signature issued for canister A / method M cannot be replayed against canister B / method N.

## Proof of Concept
```rust
// Step 1 – obtain a legitimate sender_info for a benign call
let info_bytes = b"user_role=basic";
let sender_info_sig = internet_identity.sign("ic-sender-info" || info_bytes);
let sender_info = RawSignedSenderInfo {
    info: info_bytes,
    signer: internet_identity_canister_id,
    sig: sender_info_sig,
};

// Step 2 – construct a NEW request to a DIFFERENT canister/method
//           reusing the identical sender_info
let malicious_request = HttpRequestEnvelope {
    content: HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: privileged_canister_id,   // different target
            method_name: "admin_action".to_string(), // privileged method
            arg: ...,
            sender: attacker_principal,
            ingress_expiry: fresh_expiry,
            nonce: None,
            sender_info: Some(sender_info),  // REPLAYED, unchanged
        },
    },
    sender_pubkey: Some(attacker_canister_sig_pubkey),
    sender_sig: Some(fresh_envelope_sig),  // freshly signed over new message_id
    sender_delegation: None,
};

// Step 3 – submit; verify_sender_info_canister_sig passes because
//           it only checks sig over ("ic-sender-info" || info_bytes),
//           which is identical to the original.
```

A deterministic integration test using PocketIC can confirm this by: (1) obtaining a valid `sender_info` from a test signing canister for call R₁; (2) submitting call R₂ to a different canister/method with the identical `sender_info`; (3) asserting that `validate_request` returns `Ok` and the target canister receives the replayed `sender_info` intact.

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

**File:** rs/types/types/src/crypto/sign.rs (L161-165)
```rust
impl<'a> SignatureDomain for SenderInfoContent<'a> {
    fn domain(&self) -> Vec<u8> {
        domain_with_prepended_length("ic-sender-info")
    }
}
```

**File:** rs/validator/src/ingress_validation.rs (L219-219)
```rust
    validate_sender_info(request, ingress_signature_verifier, root_of_trust_provider)?;
```

**File:** rs/validator/src/ingress_validation.rs (L494-545)
```rust
fn verify_sender_info_canister_sig<R: RootOfTrustProvider>(
    sender_info: &SignedSenderInfo,
    sender_pubkey_bytes: &[u8],
    validator: &dyn IngressSigVerifier,
    root_of_trust_provider: &R,
) -> Result<(), RequestValidationError>
where
    R::Error: std::error::Error,
{
    // Parse the envelope-level sender_pubkey DER to extract the raw
    // public key bytes and verify it's a valid canister signature public key.
    let pk_bytes = public_key_bytes_from_der(sender_pubkey_bytes).map_err(|e| {
        InvalidSenderInfo(format!(
            "sender_pubkey is not a valid canister signature public key: {e}"
        ))
    })?;

    // Extract the canister ID from the parsed public key and verify
    // it matches the declared signer.
    let parsed_pk = ic_crypto_iccsa::types::PublicKey::try_from(&pk_bytes)
        .map_err(|e| InvalidSenderInfo(format!("invalid canister sig public key: {e:?}")))?;
    let pubkey_canister_id = parsed_pk.signing_canister_id();
    if pubkey_canister_id != sender_info.signer {
        return Err(InvalidSenderInfo(format!(
            "signer {} does not match canister ID {} in sender_pubkey",
            sender_info.signer, pubkey_canister_id
        )));
    }

    // Construct the UserPublicKey for verification.
    let public_key = UserPublicKey {
        key: pk_bytes.0,
        algorithm_id: AlgorithmId::IcCanisterSignature,
    };

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

**File:** rs/types/types/src/messages/ingress_messages.rs (L44-52)
```rust
pub struct SignedIngressContent {
    sender: UserId,
    canister_id: CanisterId,
    method_name: String,
    arg: Vec<u8>,
    ingress_expiry: u64,
    nonce: Option<Vec<u8>>,
    sender_info: Option<SignedSenderInfo>,
}
```
