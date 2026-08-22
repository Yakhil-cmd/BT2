No vulnerability found for this question.

**Rationale:** The premise of the question doesn't match the actual code. There is no `try_from` function in `core/primitives/src/action/delegate.rs` that handles domain separation for signed delegate messages. The domain-separation logic actually lives in `core/primitives/src/signable_message.rs`, where `SignableMessage::new` binds a `MessageDiscriminant` (derived from a NEP number, e.g., 366 for `DelegateAction`, 611 for `DelegateActionV2`) to the message before hashing and signing [1](#0-0) .

`DelegateAction::get_nep461_hash` and `VersionedDelegateActionPayload::get_nep461_hash` each construct a `SignableMessage` with their own distinct `SignableMessageType` (`DelegateAction` vs `DelegateActionV2`), so the discriminant is baked into the borsh-serialized/hashed payload that is actually signed and later re-verified [2](#0-1) [3](#0-2) . `SignedDelegateAction::verify` and `VersionedSignedDelegateAction::verify` recompute this same domain-tagged hash and verify the signature against it, so a signature produced under one discriminant (or nonce/index) cannot verify against a payload tagged with a different discriminant [4](#0-3) [5](#0-4) .

This is already covered by existing tests that explicitly assert cross-domain/cross-version signature reuse fails: `test_signed_delegate_action_v2_verify` confirms a V1-tagged signature does not verify for a V2 payload, and `nep_366_wrong_nep` / `nep_366_wrong_msg_type` in `signable_message.rs` confirm that wrong NEP numbers or off-chain-tagged discriminants also fail verification [6](#0-5) [7](#0-6) . The `MessageDiscriminant::is_transaction` check additionally ensures the on/off-chain discriminant ranges can never collide with a plain `SignedTransaction`'s encoding [8](#0-7) .

Since the domain separator is cryptographically bound into the hash that is signed and re-verified, and both the code and existing unit tests demonstrate rejection of cross-domain signature reuse, the invariant "every signed message type has a distinct, non-reusable domain" holds. There is no reachable `try_from` in this file that performs domain-related conversion, so the specific target described in the question does not exist in this codebase.

### Citations

**File:** core/primitives/src/signable_message.rs (L97-107)
```rust
impl<'a, T: BorshSerialize> SignableMessage<'a, T> {
    pub fn new(msg: &'a T, ty: SignableMessageType) -> Self {
        let discriminant = ty.into();
        Self { discriminant, msg }
    }

    pub fn sign(&self, signer: &Signer) -> Signature {
        let bytes = borsh::to_vec(&self).expect("Failed to deserialize");
        let hash = hash(&bytes);
        signer.sign(hash.as_bytes())
    }
```

**File:** core/primitives/src/signable_message.rs (L152-161)
```rust
    /// Whether this discriminant marks a traditional `SignedTransaction`.
    pub fn is_transaction(&self) -> bool {
        // Backwards compatibility with transaction that were defined before this standard:
        // Transaction begins with `AccountId`, which is just a `String` in
        // borsh serialization, which starts with the length of the underlying
        // byte vector in little endian u32.
        // Currently allowed AccountIds are between 2 and 64 bytes.
        self.discriminant >= AccountId::MIN_LEN as u32
            && self.discriminant <= AccountId::MAX_LEN as u32
    }
```

**File:** core/primitives/src/signable_message.rs (L251-284)
```rust
    // Try to use a wrong nep number in NEP-366 signature verification.
    #[test]
    fn nep_366_wrong_nep() {
        let sender_id: AccountId = "alice.near".parse().unwrap();
        let receiver_id: AccountId = "bob.near".parse().unwrap();
        let signer = InMemorySigner::test_signer(&sender_id);

        let delegate_action = delegate_action(sender_id, receiver_id, signer.public_key());
        let wrong_nep = 777;
        let signable = SignableMessage {
            discriminant: MessageDiscriminant::new_on_chain(wrong_nep).unwrap(),
            msg: &delegate_action,
        };
        let signed = SignedDelegateAction { signature: signable.sign(&signer), delegate_action };

        assert!(!signed.verify());
    }

    // Try to use a wrong message type in NEP-366 signature verification.
    #[test]
    fn nep_366_wrong_msg_type() {
        let sender_id: AccountId = "alice.near".parse().unwrap();
        let receiver_id: AccountId = "bob.near".parse().unwrap();
        let signer = InMemorySigner::test_signer(&sender_id);

        let delegate_action = delegate_action(sender_id, receiver_id, signer.public_key());
        let correct_nep = 366;
        // here we use it as an off-chain only signature
        let wrong_discriminant = MessageDiscriminant::new_off_chain(correct_nep).unwrap();
        let signable = SignableMessage { discriminant: wrong_discriminant, msg: &delegate_action };
        let signed = SignedDelegateAction { signature: signable.sign(&signer), delegate_action };

        assert!(!signed.verify());
    }
```

**File:** core/primitives/src/action/delegate.rs (L83-90)
```rust
impl SignedDelegateAction {
    pub fn verify(&self) -> bool {
        let delegate_action = &self.delegate_action;
        let hash = delegate_action.get_nep461_hash();
        let public_key = &delegate_action.public_key;

        self.signature.verify(hash.as_ref(), public_key)
    }
```

**File:** core/primitives/src/action/delegate.rs (L176-184)
```rust
    /// Delegate action hash used for NEP-461 signature scheme which tags
    /// different messages before hashing
    ///
    /// For more details, see: [NEP-461](https://github.com/near/NEPs/pull/461)
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateActionV2);
        let bytes = borsh::to_vec(&signable).expect("failed to serialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/action/delegate.rs (L210-214)
```rust
impl VersionedSignedDelegateAction {
    pub fn verify(&self) -> bool {
        let hash = self.delegate_action.get_nep461_hash();
        self.signature.verify(hash.as_ref(), self.delegate_action.public_key())
    }
```

**File:** core/primitives/src/action/delegate.rs (L349-357)
```rust
    /// Delegate action hash used for NEP-461 signature scheme which tags
    /// different messages before hashing
    ///
    /// For more details, see: [NEP-461](https://github.com/near/NEPs/pull/461)
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
        let bytes = borsh::to_vec(&signable).expect("Failed to deserialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/action/delegate.rs (L477-487)
```rust
        // A signature under the V1 message discriminant must not verify for a
        // V2 action; V1 and V2 signing domains are disjoint.
        let versioned = VersionedDelegateActionPayload::from(delegate_action);
        let v1_tagged_signature =
            SignableMessage::new(&versioned, SignableMessageType::DelegateAction).sign(&signer);
        let forged = VersionedSignedDelegateAction {
            delegate_action: versioned,
            signature: v1_tagged_signature,
        };
        assert!(!forged.verify());
    }
```
