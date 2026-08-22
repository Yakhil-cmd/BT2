### Title
DelegateAction (meta-transaction) signature lacks a chain-domain separator, enabling cross-chain replay of relayed actions - (File: `core/primitives/src/action/delegate.rs`, `core/primitives/src/signable_message.rs`)

### Summary
The inner signature that a NEAR account owner produces to authorize a meta-transaction (`SignedDelegateAction` / `VersionedSignedDelegateAction`, NEP-366/NEP-461) is computed over a digest that binds only to `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, `public_key`, and a message-type discriminant — never to a chain/network identifier such as `chain_id` or a genesis hash. This is the same bug class as the reported issue: a signed authorization digest missing a domain separator, allowing replay of a validly-signed payload across a different execution context (there: a different chain; here: a different NEAR-protocol network/fork that shares account state).

### Finding Description
`DelegateAction::get_nep461_hash()` and `VersionedDelegateActionPayload::get_nep461_hash()` build the signed digest as: [1](#0-0) 
via `SignableMessage::new(&self, SignableMessageType::DelegateAction)` and then `hash(borsh(SignableMessage))`, where `SignableMessage` only contains a `MessageDiscriminant` (a NEP number tag) and the message itself: [2](#0-1) 

The `DelegateAction` payload that actually gets hashed and signed contains no chain-identifying field: [3](#0-2) 

Verification (`SignedDelegateAction::verify` / `VersionedSignedDelegateAction::verify`) checks the signature purely against this chain-agnostic hash and the embedded `public_key`: [4](#0-3) [5](#0-4) 

By contrast, a plain `SignedTransaction` *is* bound to a specific chain because it embeds a recent `block_hash`, which the runtime validates against the receiving chain's own recent blocks (`chain_validate`), and this is explicitly documented as the mechanism that prevents replaying transactions signed for one chain on a different (e.g., forked/mirrored) chain: [6](#0-5) [7](#0-6) 

Crucially, this `block_hash` binding exists only on the **outer** transaction (built and signed by the relayer/signer of the outer tx), not on the **inner** `DelegateAction` signature produced by the delegating account owner. The inner signature is the actual authorization the account owner gives to allow the relayer to act on their behalf, and it carries no chain/network binding at all. `max_block_height` only bounds validity by block height, which is not unique across chains/forks (multiple NEAR-protocol networks can be at the same block height range simultaneously, e.g. a "mirror"/forked target chain, per `tools/mirror`).

`nearcore`'s own tooling (`tools/mirror`) demonstrates that forked/derived NEAR networks routinely preserve the same accounts and, unless explicitly remapped, the same public keys as the source chain: [8](#0-7) 
The mirror tool must remap keys specifically to defeat the `block_hash` replay protection on outer transactions — but it does not (and cannot, since it operates at the outer-tx layer) address the inner `DelegateAction` digest, because that digest was never bound to `block_hash`/chain identity in the first place.

### Impact Explanation
If an account (same `sender_id`, same access `public_key`) exists on two different NEAR-protocol networks that share genesis/account state — which is the explicit design point of the `mirror` tooling, and also plausible for testnet forks, private/enterprise NEAR-based chains, or accidental chain-id reuse — a `DelegateAction` signature obtained (or observed) on chain A remains fully valid input to `apply_delegate_action` on chain B, as long as:
- the `max_block_height` bound hasn't been exceeded on chain B, and
- the access key `nonce` on chain B hasn't yet advanced past the signed nonce.

Any actor with access to a previously-broadcast (or leaked) signed `DelegateAction` — e.g. a relayer, or anyone observing the mempool/chunks on chain A — can wrap it in a freshly-signed outer transaction (with a valid current `block_hash` for chain B) and submit it to chain B. Because `SignedDelegateAction::verify`/`VersionedSignedDelegateAction::verify` only check the chain-agnostic digest, the runtime will execute the delegated actions (`AddKey`, `Transfer`, `FunctionCall`, etc.) against the account on chain B without the owner's intent for that specific network. This is an authorization-bypass / unauthorized state-and-balance-change primitive: actions the account owner signed for use on one network execute unexpectedly on another.

### Likelihood Explanation
Exploitability requires two NEAR-protocol networks that share the same account namespace and unmapped access keys — a real, supported nearcore scenario (state-forked "mirror" target chains, migration/test networks cloned from mainnet/testnet snapshots without key remapping, or accidentally identical `chain_id`/state setups). Given that requirement, the replay itself needs no privileged role: any relayer or observer holding a valid `SignedDelegateAction` blob and network access to submit an outer transaction to the second chain can trigger it, before `max_block_height` elapses and before the target account's nonce is consumed there. Likelihood is Medium — comparable to the original report's rating — since it depends on an operational precondition (shared account/key state across networks) rather than a universally-reachable single-chain bug.

### Recommendation
Fold a chain/network domain separator into the `DelegateAction`/`DelegateActionV2` signed digest — e.g. include the receiving chain's `chain_id` (or genesis hash) inside the `SignableMessage`/payload that is hashed and signed in `get_nep461_hash()` (`core/primitives/src/action/delegate.rs`, `core/primitives/src/signable_message.rs`), mirroring the domain separation NEAR already relies on for outer transactions via `block_hash`/`chain_validate`. This should be versioned analogously to the existing `SignableMessageType::DelegateAction` vs `DelegateActionV2` scheme so old signatures remain rejected under the new scheme without breaking replay-protection guarantees.

### Proof of Concept
1. Network A (`chain_id = "mainnet"`) and Network B (`chain_id = "mirror-net"`, or any forked/derived NEAR network) share account `alice.near` with the same full-access `public_key`, produced e.g. via `tools/mirror` state-fork without key remapping, or an operator error that reuses genesis/account state.
2. Alice signs a `DelegateAction{sender_id: "alice.near", receiver_id: "bob.near", actions: [Transfer{...}], nonce: N, max_block_height: H, public_key: PK}` intending it to be relayed only on Network A, per `SignedDelegateAction::sign` in `core/primitives/src/action/delegate.rs`.
3. A relayer (or any party who observes this `SignedDelegateAction` in a chunk/mempool on Network A) copies the identical `delegate_action` + `signature` bytes.
4. On Network B, the relayer wraps the same `SignedDelegateAction` in a freshly-built outer `SignedTransaction` addressed to `alice.near`, signed by the relayer with a valid recent `block_hash` for Network B.
5. `apply_delegate_action` on Network B calls `SignedDelegateAction::verify()`, which recomputes `get_nep461_hash()` — identical to the one computed on Network A since no chain identity is included — and the signature check succeeds.
6. As long as Network B's block height is still below `H` and its copy of the access key's nonce is still below `N`, the `Transfer` action executes on Network B, moving Alice's `bob.near`-directed funds there even though Alice never intended to authorize anything on Network B.

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

**File:** core/primitives/src/action/delegate.rs (L210-214)
```rust
impl VersionedSignedDelegateAction {
    pub fn verify(&self) -> bool {
        let hash = self.delegate_action.get_nep461_hash();
        self.signature.verify(hash.as_ref(), self.delegate_action.public_key())
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

**File:** core/primitives/src/signable_message.rs (L56-65)
```rust
/// A wrapper around a message that should be signed using this scheme.
///
/// Only used for constructing a signature, not used to transmit messages. The
/// discriminant prefix is implicit and should be known by the receiver based on
/// the context in which the message is received.
#[derive(BorshSerialize)]
pub struct SignableMessage<'a, T> {
    pub discriminant: MessageDiscriminant,
    pub msg: &'a T,
}
```

**File:** docs/architecture/how/tx_routing.md (L31-34)
```markdown
**Fun fact:** the `Transaction` object also contains some fields to prevent
attacks: like `nonce` to prevent replay attack, and `block_hash` to limit the
validity of the transaction (it must be added within
`transaction_validity_period` (defined in genesis) blocks of `block_hash`).
```

**File:** tools/mirror/README.md (L1-12)
```markdown
## Transaction Mirror

This is some code that tries to help with the following: We have some
chain, let's call it the "source chain", producing blocks and chunks
with transactions as usual, and we have another chain, let's call it
the "target chain" that starts from state forked from the source
chain. Usually this would be done by using the `neard view-state
dump-state` command, and using the resulting genesis and records file
as the start of the target chain. What we want is to then periodically
send the transactions appearing in the source chain after the fork
point to the target chain. Ideally, the traffic we see in the target
chain will be very similar to the traffic in the source chain.
```

**File:** tools/mirror/README.md (L14-21)
```markdown
The first approach we might try is to just send the source chain
transactions byte-for-byte unaltered to the target chain. This almost
works, but not quite, because the `block_hash` field in the
transactions will be rejected. This means we have no choice but to
replace the accounts' public keys in the original forked state, so
that we can sign transactions with a valid `block_hash` field. So the
way we'll use this is that we'll generate the forked state from the
source chain using the usual `dump-state` command, and then run:
```
