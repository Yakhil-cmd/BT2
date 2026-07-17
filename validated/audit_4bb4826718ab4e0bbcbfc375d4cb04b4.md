### Title
Cross-Network Replay of `SignedDelegateAction` Due to Missing Chain-Specific Domain Binding — (`File: core/primitives/src/action/delegate.rs`)

---

### Summary

`DelegateAction::get_nep461_hash()` produces a signed payload that contains no chain-specific identifier. Unlike a regular `Transaction`, which includes a `block_hash` that anchors it to a specific NEAR network, the inner `DelegateAction` signed payload is bound only to a NEP-number discriminant (`366` or `611`) that is identical across every NEAR network (mainnet, testnet, betanet, any fork). An unprivileged attacker who obtains a valid `SignedDelegateAction` from one network can wrap it in a fresh outer `Transaction` on a different network and have it accepted and executed there.

---

### Finding Description

`DelegateAction::get_nep461_hash()` constructs the signed digest as:

```
SHA-256( borsh(MessageDiscriminant(NEP_366)) || borsh(DelegateAction) )
``` [1](#0-0) 

`DelegateAction` contains `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, and `public_key`. [2](#0-1) 

None of these fields is chain-specific. The `MessageDiscriminant` is a fixed NEP number, not a genesis hash or chain ID. [3](#0-2) [4](#0-3) 

By contrast, a regular `Transaction` includes `block_hash`, which is a hash of a block on the specific chain the transaction targets, providing chain-domain binding: [5](#0-4) 

`SignedDelegateAction::verify()` checks only the signature against `get_nep461_hash()` — no chain context is consulted: [6](#0-5) 

The runtime's `validate_delegate_action_key` enforces only a nonce bound and a `max_block_height` bound, neither of which is chain-specific: [7](#0-6) 

---

### Impact Explanation

An attacker who obtains a `SignedDelegateAction` that Alice created on testnet can:

1. Wrap it verbatim inside a new `Transaction` whose `signer_id` is the attacker's own relayer account on **mainnet**, with a valid mainnet `block_hash`.
2. Submit to mainnet. The outer transaction signature is the attacker's own (valid). The inner `DelegateAction` signature verification calls `get_nep461_hash()` — which produces the same hash on mainnet as on testnet — and passes.
3. The nonce check passes if Alice's mainnet access-key nonce is lower than the nonce embedded in the testnet-signed action.
4. All inner `actions` execute on mainnet under Alice's `sender_id`: token transfers drain Alice's mainnet balance, `AddKey`/`DeleteKey` alter her mainnet access keys, `FunctionCall` invokes contracts on her behalf.

Impact: **Critical** — arbitrary unauthorized execution of actions on a victim's mainnet account, including full balance drain and key takeover.

---

### Likelihood Explanation

The preconditions are:

- Alice's account ID exists on both networks (trivially true for any account created on both).
- Alice's access key (same `public_key`) is registered on both networks — common for developers and wallets that reuse key material across testnet and mainnet.
- The mainnet access-key nonce is lower than the nonce in the testnet-signed action — likely when the mainnet account is less active than the testnet account.
- The attacker observes a `SignedDelegateAction` in flight (e.g., via a public relayer API, mempool gossip, or off-chain communication).

These conditions are realistic for a significant fraction of NEAR users. Likelihood: **Medium**.

---

### Recommendation

Include a chain-specific domain separator in the `DelegateAction` signed payload. The canonical approach is to add the genesis block hash (or a dedicated chain-ID field) to `DelegateAction` and incorporate it into `get_nep461_hash()`. A minimal change:

```rust
pub struct DelegateAction {
    pub sender_id: AccountId,
    pub receiver_id: AccountId,
    pub actions: Vec<NonDelegateAction>,
    pub nonce: Nonce,
    pub max_block_height: BlockHeight,
    pub public_key: PublicKey,
    // NEW: chain-domain binding, set to genesis block hash
    pub chain_id: CryptoHash,
}
```

Alternatively, incorporate the genesis hash into `SignableMessage` itself so that all future message types inherit the binding automatically. The runtime must then verify that `delegate_action.chain_id` matches the local chain's genesis hash before accepting the action.

---

### Proof of Concept

**Setup**: Alice has account `alice.near` on both testnet and mainnet, with the same ED25519 key pair registered. Mainnet access-key nonce = 5; testnet access-key nonce = 10.

**Step 1 — Alice signs on testnet** (legitimately, to pay a relayer):
```rust
let delegate_action = DelegateAction {
    sender_id: "alice.near".parse().unwrap(),
    receiver_id: "bob.near".parse().unwrap(),
    actions: vec![transfer(100_000_000)],
    nonce: 11,                    // valid on testnet (> 10)
    max_block_height: 999_999_999,
    public_key: alice_pubkey,
};
let signed = SignedDelegateAction::sign(&alice_signer, delegate_action);
// signed.verify() == true on testnet
```

**Step 2 — Attacker replays on mainnet**:
```rust
// Attacker wraps the SAME signed in a mainnet transaction
let mainnet_tx = SignedTransaction::from_actions(
    attacker_nonce,
    attacker_account,          // attacker pays gas
    "alice.near".parse().unwrap(),
    &attacker_signer,
    vec![Action::Delegate(Box::new(signed))],  // testnet-signed, unchanged
    mainnet_block_hash,        // valid mainnet block hash
);
// Submit to mainnet RPC
```

**Step 3 — Mainnet runtime**:
- Outer tx signature: valid (attacker's key).
- `SignedDelegateAction::verify()`: calls `get_nep461_hash()` → same hash as testnet → **passes**.
- Nonce check: `11 > 5` → **passes**.
- `max_block_height` check: `999_999_999` far in the future → **passes**.
- Result: 100 NEAR transferred from Alice's **mainnet** account to Bob, without Alice's consent. [6](#0-5) [8](#0-7) [9](#0-8)

### Citations

**File:** core/primitives/src/action/delegate.rs (L46-64)
```rust
pub struct DelegateAction {
    /// Signer of the delegated actions
    pub sender_id: AccountId,
    /// Receiver of the delegated actions.
    pub receiver_id: AccountId,
    /// List of actions to be executed.
    ///
    /// With the meta transactions MVP defined in NEP-366, nested
    /// DelegateActions are not allowed. A separate type is used to enforce it.
    pub actions: Vec<NonDelegateAction>,
    /// Nonce to ensure that the same delegate action is not sent twice by a
    /// relayer and should match for given account's `public_key`.
    /// After this action is processed it will increment.
    pub nonce: Nonce,
    /// The maximal height of the block in the blockchain below which the given DelegateAction is valid.
    pub max_block_height: BlockHeight,
    /// Public key used to sign this delegated action.
    pub public_key: PublicKey,
}
```

**File:** core/primitives/src/action/delegate.rs (L83-95)
```rust
impl SignedDelegateAction {
    pub fn verify(&self) -> bool {
        let delegate_action = &self.delegate_action;
        let hash = delegate_action.get_nep461_hash();
        let public_key = &delegate_action.public_key;

        self.signature.verify(hash.as_ref(), public_key)
    }

    pub fn sign(singer: &Signer, delegate_action: DelegateAction) -> Self {
        let signature = singer.sign(delegate_action.get_nep461_hash().as_bytes());
        Self { delegate_action, signature }
    }
```

**File:** core/primitives/src/action/delegate.rs (L353-357)
```rust
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
        let bytes = borsh::to_vec(&signable).expect("Failed to deserialize");
        hash(&bytes)
    }
```

**File:** core/primitives/src/signable_message.rs (L18-25)
```rust
const MIN_ON_CHAIN_DISCRIMINANT: u32 = 1 << 30;
const MAX_ON_CHAIN_DISCRIMINANT: u32 = (1 << 31) - 1;
const MIN_OFF_CHAIN_DISCRIMINANT: u32 = 1 << 31;
const MAX_OFF_CHAIN_DISCRIMINANT: u32 = u32::MAX;

// NEPs currently included in the scheme
const NEP_366_META_TRANSACTIONS: u32 = 366;
const NEP_611_GAS_KEYS: u32 = 611;
```

**File:** core/primitives/src/signable_message.rs (L51-54)
```rust
pub struct MessageDiscriminant {
    /// The unique prefix, serialized in little-endian by borsh.
    discriminant: u32,
}
```

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

**File:** core/primitives/src/transaction.rs (L33-48)
```rust
pub struct TransactionV0 {
    /// An account on which behalf transaction is signed
    pub signer_id: AccountId,
    /// A public key of the access key which was used to sign an account.
    /// Access key holds permissions for calling certain kinds of actions.
    pub public_key: PublicKey,
    /// Nonce is used to determine order of transaction in the pool.
    /// It increments for a combination of `signer_id` and `public_key`
    pub nonce: Nonce,
    /// Receiver account for this transaction
    pub receiver_id: AccountId,
    /// The hash of the block in the blockchain on top of which the given transaction is valid
    pub block_hash: CryptoHash,
    /// A list of actions to be applied
    pub actions: Vec<Action>,
}
```

**File:** runtime/runtime/src/actions.rs (L604-622)
```rust
    if delegate_nonce.nonce() <= current_nonce {
        result.result = Err(ActionErrorKind::DelegateActionInvalidNonce {
            delegate_nonce: delegate_nonce.nonce(),
            ak_nonce: current_nonce,
        }
        .into());
        return Ok(());
    }

    let upper_bound = apply_state.block_height
        * near_primitives::account::AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER;
    if delegate_nonce.nonce() >= upper_bound {
        result.result = Err(ActionErrorKind::DelegateActionNonceTooLarge {
            delegate_nonce: delegate_nonce.nonce(),
            upper_bound,
        }
        .into());
        return Ok(());
    }
```
