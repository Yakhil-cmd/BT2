### Title
Cross-network replay of signed `DelegateAction` meta-transactions due to missing chain/network identifier in the NEP‑366 signature ([File: core/primitives/src/action/delegate.rs])

### Summary
A `DelegateAction` (NEP‑366 meta-transaction) is signed off-chain by the sender and later wrapped and submitted on-chain by a relayer. The signed payload contains no network- or chain-specific binding (no genesis hash, chain id, or block hash), unlike ordinary `SignedTransaction`s, which are anchored to a specific `block_hash` of the chain they were signed for. This mirrors the Harpie `changeRecipientAddress()` bug class: signed data lacking a chain discriminator can be captured and replayed on a different chain that shares account/key state.

### Finding Description
An ordinary NEAR transaction (`TransactionV0`) includes `block_hash: CryptoHash` — "the hash of the block in the blockchain on top of which the given transaction is valid" [1](#0-0) . Because block hashes are unique per-chain and only valid within `transaction_validity_period`, this field implicitly binds a signed transaction to one specific chain — a transaction signed against a mainnet block hash cannot be replayed on testnet (or a forked network) because that block hash will never exist there.

`DelegateAction`, introduced for meta-transactions, has no equivalent binding. Its signed fields are only `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, and `public_key`: [2](#0-1) 

The signature is computed over these fields tagged only with a NEP-number discriminant (366 for V1, 611 for gas-key V2), via `get_nep461_hash`/`SignableMessage`, with no chain/network identifier included: [3](#0-2) [4](#0-3) 

`SignedDelegateAction::verify()` / `VersionedSignedDelegateAction::verify()` only check that the signature matches this NEP-tagged hash and public key — again with no chain binding: [5](#0-4) [6](#0-5) 

The only replay-limiting factors are the sender's access-key `nonce` (checked against on-chain state) and `max_block_height` (an absolute height bound) — both of which are properties of the executing chain's local state, not properties that uniquely identify *which* chain the signer intended. If a sender's account (same `sender_id`, same `public_key`, and compatible nonce/height state) exists identically on two different NEAR networks — e.g. mainnet vs. testnet where a user reused the same seed phrase to register the same account name on both, or a forked/mirrored network produced by `tools/fork-network` or `tools/mirror` (whose own docs acknowledge that if security is not cared about, "we can just use the bytes of the public key directly as the private key" for the target chain) — a `SignedDelegateAction` captured off-chain and intended for chain A can be relayed as-is by any relayer into chain B, where it will pass `verify()` and execute the sender's actions there without their consent for that chain.

This is structurally the same root cause as the Harpie report: a signature over application data omits a chain-identifying value, so a signed authorization for one chain is valid data for another.

### Impact Explanation
If exploitable (i.e., the same `sender_id`/`public_key`/nonce state coincides across two NEAR networks a user interacts with, such as mirrored/forked test networks explicitly designed by nearcore tooling to reuse key material, or dual mainnet/testnet account setups), a captured `DelegateAction` could be replayed by any relayer to execute arbitrary authorized actions (transfers, `AddKey`, contract calls) on the unintended network — an unauthorized state/balance change executed via the account's own valid signature but on the wrong chain.

### Likelihood Explanation
Likelihood is limited: it requires that the identical `sender_id` + `public_key` + valid nonce/`max_block_height` window exist simultaneously on two networks reachable to an attacker/relayer. This is a real but narrower precondition than the original Harpie report (which itself was accepted by the audit team under the analogous assumption "the contract address is the same across chains"). Nearcore's own `tools/mirror` and `tools/fork-network` explicitly create scenarios where key material can be shared/derived deterministically across a source and target chain, which is the most concrete reachable trigger for this precondition; ordinary independent mainnet/testnet accounts are less likely to coincide unless a user deliberately mirrors their setup.

### Recommendation
Include a chain/network-identifying value (e.g., the genesis hash or a configured `chain_id`/network id, analogous to what the Wallet Contract's Ethereum-style `chain_id` check already enforces for RLP transactions in `runtime/near-wallet-contract`) inside the NEP‑366/NEP‑611 signed payload (`DelegateAction`/`DelegateActionV2`) and validate it during `verify()`/`apply_delegate_action`, so a `SignedDelegateAction` produced for one network cannot be replayed as valid signed data on another.

### Proof of Concept
1. On network A, Alice signs a `SignedDelegateAction` via `SignedDelegateAction::sign(&signer, delegate_action)` [7](#0-6) , delegating e.g. an `AddKeyAction` (add a new full-access key), intended to be relayed only on network A.
2. Alice's account exists with the same `sender_id`, `public_key`, and coincidentally-compatible access-key nonce on network B (e.g., a `tools/mirror`/`tools/fork-network`-produced network sharing key material, per `tools/mirror/README.md`).
3. An attacker/relayer intercepts the `SignedDelegateAction` (it is transmitted off-chain to a relayer per the meta-tx flow described in `docs/architecture/how/meta-tx.md`) and instead wraps it into a transaction submitted on network B.
4. `VersionedSignedDelegateAction::verify()` / `SignedDelegateAction::verify()` succeeds on network B because the signed hash contains no network-distinguishing data, and `apply_delegate_action` proceeds to add the new full-access key on network B without Alice's intent for that network.

### Citations

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

**File:** core/primitives/src/action/delegate.rs (L83-96)
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
}
```

**File:** core/primitives/src/action/delegate.rs (L210-220)
```rust
impl VersionedSignedDelegateAction {
    pub fn verify(&self) -> bool {
        let hash = self.delegate_action.get_nep461_hash();
        self.signature.verify(hash.as_ref(), self.delegate_action.public_key())
    }

    pub fn sign(signer: &Signer, delegate_action: VersionedDelegateActionPayload) -> Self {
        let signature = signer.sign(delegate_action.get_nep461_hash().as_bytes());
        Self { delegate_action, signature }
    }
}
```

**File:** core/primitives/src/action/delegate.rs (L344-357)
```rust
impl DelegateAction {
    pub fn get_actions(&self) -> Vec<Action> {
        self.actions.iter().map(|a| a.clone().into()).collect()
    }

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

**File:** core/primitives/src/signable_message.rs (L97-108)
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
}
```
