No vulnerability found for this question.

The `try_from` in `core/primitives/src/signable_message.rs` is `impl TryFrom<MessageDiscriminant> for SignableMessageType`, which operates purely on an already-parsed `MessageDiscriminant` struct containing a single `u32` field [1](#0-0) . The conversion logic only performs integer range comparisons and subtraction against constants (`MIN_ON_CHAIN_DISCRIMINANT`, `MAX_ON_CHAIN_DISCRIMINANT`, etc.) to classify the discriminant and return an enum variant or a typed error [2](#0-1) . There is no decoding of variable-length collections (`Vec`, `String`, etc.) or any allocation based on attacker-declared lengths anywhere in this function — the `BorshDeserialize` for `MessageDiscriminant` itself is a `#[derive]`d implementation for a fixed 4-byte `u32` field [3](#0-2) , so decoding it can never allocate more than 4 bytes regardless of payload content.

Since the targeted function contains no length-prefixed collection decoding and performs no heap allocation proportional (or disproportional) to any attacker-controlled length field, the premise of the question — that `try_from` can be driven to allocate memory disproportionate to the real payload size — does not hold for this code.

### Citations

**File:** core/primitives/src/signable_message.rs (L36-54)
```rust
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    ProtocolSchema,
)]
pub struct MessageDiscriminant {
    /// The unique prefix, serialized in little-endian by borsh.
    discriminant: u32,
}
```

**File:** core/primitives/src/signable_message.rs (L197-215)
```rust
impl TryFrom<MessageDiscriminant> for SignableMessageType {
    type Error = ReadDiscriminantError;

    fn try_from(discriminant: MessageDiscriminant) -> Result<Self, Self::Error> {
        if discriminant.is_transaction() {
            Err(Self::Error::TransactionFound)
        } else if let Some(nep) = discriminant.on_chain_nep() {
            match nep {
                NEP_366_META_TRANSACTIONS => Ok(Self::DelegateAction),
                NEP_611_GAS_KEYS => Ok(Self::DelegateActionV2),
                _ => Err(Self::Error::UnknownOnChainNep(nep)),
            }
        } else if let Some(nep) = discriminant.off_chain_nep() {
            Err(Self::Error::UnknownOffChainNep(nep))
        } else {
            Err(Self::Error::UnknownMessageType)
        }
    }
}
```
