Audit Report

## Title
`sender_info.sig` Included in `MessageId` Hash Enables Replay of State-Mutating Calls via Non-Unique Canister Signatures — (`rs/types/types/src/messages/http.rs`, `rs/types/types/src/messages/ingress_messages.rs`)

## Summary

`representation_independent_hash_call_or_query` includes the `sig` field of `sender_info` in the `MessageId` hash. Because IC canister signatures are structurally non-unique — the same content certified at two different block heights produces two different but equally valid CBOR witnesses — an attacker who controls a canister can craft two messages that are semantically identical but carry distinct `MessageId`s. Both pass `validate_sender_info` independently, both are admitted to the ingress pool, and `ValidSetRuleImpl::is_duplicate` (keyed solely on `MessageId`) fails to detect the duplication, causing the same state-mutating call to be inducted and executed twice.

## Finding Description

**Root cause — `sig` is hashed into `MessageId`.**

`representation_independent_hash_call_or_query` in `rs/types/types/src/messages/http.rs` inserts the full `sender_info` map — including `sig` — into the hash: [1](#0-0) 

`SignedIngressContent::id()` passes `sig` directly to this function: [2](#0-1) 

Two messages identical in every field except `sender_info.sig` therefore produce different `MessageId`s.

**Deduplication is keyed solely on `MessageId`.**

`ValidSetRuleImpl::is_duplicate` checks only the ingress history keyed by `MessageId`: [3](#0-2) 

`induct_messages` skips a message only when `is_duplicate` returns `true`: [4](#0-3) 

`IngressSetChain::contains` and the ingress pool are also keyed on `IngressMessageId` (which embeds `MessageId`), so both messages are admitted independently: [5](#0-4) 

**Canister signatures are non-unique.**

A canister signature is a CBOR `{certificate, tree}` where `certificate` is a subnet BLS certification of the canister's `certified_data` at a specific block height. The same `info_bytes` certified at two different rounds produces two different witnesses (different Merkle proofs from different state-tree roots), both of which pass `verify_sender_info_canister_sig`: [6](#0-5) 

The `CanisterSigner::sign` implementation in the test suite confirms this: each call to `certify_variable` fetches a fresh certificate from the live subnet, so two calls at different heights yield different CBOR blobs: [7](#0-6) 

**`validate_sender_info` is called per-message, not cross-message.**

`validate_request_content` validates each message's envelope signature and `sender_info` independently. There is no cross-message deduplication at the validation layer that would detect two messages with the same `info`/`signer` but different `sig`: [8](#0-7) 

**Exploit flow:**

1. Attacker deploys canister C.
2. C certifies `hash(SenderInfoContent(info_bytes))` at round R1 → witness W1.
3. C certifies the same data at round R2 → witness W2 (W1 ≠ W2).
4. Attacker constructs two ingress messages with identical `(sender, canister_id, method_name, arg, ingress_expiry, nonce)` but `sender_info.sig = W1` vs `sender_info.sig = W2`.
5. Attacker computes `MessageId1 = hash(fields + W1)` and `MessageId2 = hash(fields + W2)`.
6. Attacker produces valid envelope canister signatures over `MessageId1` and `MessageId2` respectively (C can certify any content).
7. Both messages pass `validate_request_content`. Both have distinct `MessageId`s. `is_duplicate` returns `false` for both. Both are inducted and executed.

## Impact Explanation

The replay-protection invariant is violated: the same state-mutating call executes twice. Concrete impact includes double-spending tokens held by canister C, double-executing privileged operations canister C is authorized to perform, and draining cycles from a target canister. This maps to the **High** impact class: unauthorized access to canister-controlled funds / significant ledger or infrastructure security impact with concrete user or protocol harm, exploitable by any unprivileged user who can deploy a canister.

## Likelihood Explanation

- Requires only a deployed canister, which is permissionless on the IC.
- No threshold corruption, no admin key, no social engineering.
- Two sequential `certified_data_set` + `data_certificate` calls suffice to obtain W1 and W2.
- The `sender_info` feature is production code with a full test harness (`CanisterSigner`) that already demonstrates the non-uniqueness property.
- Fully local-testable with the existing `StateMachine` / `CanisterSigner` infrastructure.

## Recommendation

Remove `sig` from the `MessageId` hash. Only `info` and `signer` are semantically meaningful for message identity; `sig` is an authentication proof that must be validated but must not affect deduplication. Change `representation_independent_hash_call_or_query` to omit `sig` from the `sender_info` sub-map:

```rust
if let Some(RawSignedSenderInfoSlices { info, signer, .. }) = sender_info {
    map.insert(
        "sender_info",
        Map(btreemap! {
            "info"   => Bytes(info),
            "signer" => Bytes(signer),
            // sig intentionally excluded from MessageId
        }),
    );
}
```

This aligns with the `ic_agent` library's existing behavior, which already excludes `sender_info` from the request ID computation.

## Proof of Concept

Using the existing `CanisterSigner` test harness and `StateMachine`:

```rust
// Two certifications of the same info_bytes at different rounds → different witnesses
let sig1 = signer.sign(&SenderInfoContent(&info_bytes).as_signed_bytes()).await; // round R1
let sig2 = signer.sign(&SenderInfoContent(&info_bytes).as_signed_bytes()).await; // round R2
assert_ne!(sig1, sig2); // different CBOR witnesses, same semantic content

let make_msg = |sig: Vec<u8>| -> SignedIngress { /* identical fields, only sig differs */ };

let msg1 = make_msg(sig1);
let msg2 = make_msg(sig2);
assert_ne!(msg1.id(), msg2.id()); // different MessageIds due to sig in hash

// Submit both; both pass validate_request_content; both inducted
env.submit_signed_ingress(msg1).unwrap();
env.submit_signed_ingress(msg2).unwrap();
env.execute_round();

// Execution count == 2: replay-protection violated
assert_eq!(execution_count, 2);
```

### Citations

**File:** rs/types/types/src/messages/http.rs (L68-77)
```rust
    if let Some(RawSignedSenderInfoSlices { info, signer, sig }) = sender_info {
        map.insert(
            "sender_info",
            Map(btreemap! {
                "info" => Bytes(info),
                "signer" => Bytes(signer),
                "sig" => Bytes(sig),
            }),
        );
    }
```

**File:** rs/types/types/src/messages/ingress_messages.rs (L113-130)
```rust
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

**File:** rs/messaging/src/scheduling/valid_set_rule.rs (L206-208)
```rust
    fn is_duplicate(&self, state: &ReplicatedState, msg: &SignedIngress) -> bool {
        state.get_ingress_status(&msg.content().id()) != &IngressStatus::Unknown
    }
```

**File:** rs/messaging/src/scheduling/valid_set_rule.rs (L349-358)
```rust
        for msg in msgs {
            let message_id = msg.content().id();
            if !self.is_duplicate(state, &msg) {
                self.induct_message(state, msg, current_round);
            } else {
                self.observe_inducted_ingress_status(LABEL_VALUE_DUPLICATE);
                debug!(self.log, "Didn't induct duplicate message {}", message_id);
            }
        }
        self.observe_ingress_history_size(state.total_ingress_memory_taken());
```

**File:** rs/ingress_manager/src/ingress_selector.rs (L740-750)
```rust
impl<T: IngressSetQuery> IngressSetQuery for IngressSetChain<'_, T> {
    fn contains(&self, msg_id: &IngressMessageId) -> bool {
        if self.first.contains(msg_id) {
            true
        } else {
            self.next
                .as_ref()
                .map(|set| set.contains(msg_id))
                .unwrap_or(false)
        }
    }
```

**File:** rs/validator/src/ingress_validation.rs (L196-221)
```rust
fn validate_request_content<C: HttpRequestContent, R: RootOfTrustProvider>(
    request: &HttpRequest<C>,
    ingress_signature_verifier: &dyn IngressSigVerifier,
    current_time: Time,
    root_of_trust_provider: &R,
) -> Result<CanisterIdSet, RequestValidationError>
where
    R::Error: std::error::Error,
{
    validate_nonce(request)?;
    // Validate the envelope signature first (cheap check) before performing
    // expensive canister signature verification in validate_sender_info.
    let targets = validate_user_id_and_signature(
        ingress_signature_verifier,
        &request.sender(),
        &request.id(),
        match request.authentication() {
            Authentication::Anonymous => None,
            Authentication::Authenticated(signature) => Some(signature),
        },
        current_time,
        root_of_trust_provider,
    )?;
    validate_sender_info(request, ingress_signature_verifier, root_of_trust_provider)?;
    Ok(targets)
}
```

**File:** rs/validator/src/ingress_validation.rs (L494-544)
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
```

**File:** rs/tests/crypto/ingress_verification_test.rs (L324-370)
```rust
    pub async fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ic_certification::{HashTree, labeled, leaf};
        use ic_crypto_sha2::Sha256;
        use serde::Serialize;
        use serde_bytes::ByteBuf;

        let seed_hash = Sha256::hash(&self.seed);
        let msg_hash = Sha256::hash(message);
        let sig_tree = labeled(b"sig", labeled(seed_hash, labeled(msg_hash, leaf(b""))));

        let mut certificate_cbor = self.certify_variable(&sig_tree.digest()).await;

        if let Some(rng_seed) = self.random_certificate_signature_rng_seed {
            let rng = &mut StdRng::from_seed(rng_seed);
            certificate_cbor = resign_certificate_with_random_signature(&certificate_cbor, rng);
        }

        #[derive(serde::Serialize)]
        struct CanisterSignature {
            certificate: ByteBuf,
            tree: HashTree,
        }
        let canister_sig = CanisterSignature {
            certificate: ByteBuf::from(certificate_cbor),
            tree: sig_tree,
        };
        // serialize to self-describing CBOR
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        canister_sig.serialize(&mut serializer).unwrap();
        serializer.into_inner()
    }

    async fn certify_variable(&self, variable_data: &[u8]) -> Vec<u8> {
        use ic_universal_canister::wasm;

        let _ = self
            .canister
            .update(wasm().certified_data_set(variable_data).reply().build())
            .await
            .expect("failed to call universal canister to set certified data");

        self.canister
            .query(wasm().data_certificate().append_and_reply().build())
            .await
            .expect("failed to call universal canister to get data certificate")
    }
```
