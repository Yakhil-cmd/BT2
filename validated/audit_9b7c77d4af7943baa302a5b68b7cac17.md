### Title
Access key nonce reset on `DeleteKey`+`AddKey` recreation permits replay of previously-executed signed transactions - ([File: runtime/runtime/src/access_keys.rs])

### Summary
When an access key with a given public key is deleted and later re-added with the *same* public key, `add_regular_key` unconditionally resets the key's nonce to a value computed only from the current block height, discarding all memory of the previous (deleted) key's nonce. Because the nonce is the sole anti-replay counter, and the new floor value is not guaranteed to exceed the highest nonce previously consumed by that public key, an attacker who has captured an old, already-executed signed transaction can resubmit it successfully after the account owner deletes and recreates the same public key, as long as the old transaction's `block_hash` is still inside `transaction_validity_period`.

### Finding Description
The nonce for a key is only ever checked monotonically against the value currently stored in state: [1](#0-0) 

When a key is deleted, its trie entry (including its nonce) is fully removed: [2](#0-1) 

When the same public key is added back (a new `AddKey` action, allowed because the old entry no longer exists), the nonce is *not* restored from any historical record — it is simply recomputed from the current block height: [3](#0-2) [4](#0-3) 

This directly contradicts the documented safety requirement for key re-creation: [5](#0-4) 

The documentation states that a recreated key reusing the same public key *should* inherit the old nonce "to avoid replaying old transactions again," but the implementation cannot do this (the old nonce is gone once the key is deleted) and instead relies purely on the block-height-derived floor `(block_height - 1) * 1e6` as a heuristic replacement. This heuristic only works if the previously stored nonce for that key was always below the new floor. Since a normal access key's nonce is itself only bounded by `tx_nonce < block_height * 1e6` (the upper-bound check in `verify_nonce`), a nonce already in use near the top of that range (which is architecturally encouraged, since NEAR's own convention is to base nonces on `(block_height - 1) * 1e6`) can exceed the new floor computed for a `DeleteKey`+`AddKey` pair executed at a nearby block height.

### Impact Explanation
If the previously-stored nonce for a public key exceeds the new block-height-derived floor at the time of key recreation, any older signed transaction with a nonce between the new floor and the old high-water mark — including transactions that were already broadcast and executed — becomes valid again under the recreated key. An attacker who retained a copy of such a transaction (e.g., observed on the network, or a relayer) can resubmit it and have it re-executed as long as its referenced `block_hash` is still within `transaction_validity_period` (`chain/chain/src/store/utils.rs`, `check_transaction_validity_period`). Re-execution of an old signed transaction (e.g., a `Transfer`, `FunctionCall`, or other authorizing action) causes an unauthorized repeat of a previously-approved action/state or balance change.

### Likelihood Explanation
Exploitation requires: (1) an attacker possessing a previously signed and already-executed transaction whose `block_hash` is still within the validity window, and (2) the victim key holder performing `DeleteKey` + `AddKey` for the same public key at a block height close enough that the new floor does not exceed the old nonce. This is a narrower, specific sequence of events (not attacker-controlled end-to-end, since it depends on the victim's own key-rotation timing and nonce history), so likelihood is low, matching the low-likelihood/high-impact classification of the original report's bug class.

### Recommendation
When re-adding a deleted access key with the same public key, do not rely solely on the block-height floor. Either (a) prevent immediate reuse of a deleted public key within the same account for some cooldown period, or (b) require/allow the caller to specify a nonce that must exceed any previously observed nonce for that public key (tracked via a persistent nonce watermark that survives key deletion), consistent with the intent documented in `docs/DataStructures/AccessKey.md`.

### Proof of Concept
1. Victim's account has a `FullAccess` key `PK` used over time, with its stored nonce approaching `(N-1)*1e6` at block height `N` (consistent with NEAR's own nonce convention).
2. Victim signs and submits `TX_old` with nonce `n_old` close to that value; it executes successfully at block `N`.
3. Attacker observes and stores `TX_old`'s raw signed bytes (including its `block_hash`, which is still within `transaction_validity_period`).
4. At a later block `M` (still within the validity window, `M` close to `N`), the victim submits a batched `DeleteKey(PK)` + `AddKey(PK, ...)` transaction (e.g., rotating permissions while keeping the same key material for convenience).
5. `add_regular_key` resets `PK`'s nonce to `(M-1)*1e6`, per `access_keys.rs:240`. If `(M-1)*1e6 < n_old`, the floor is below the previously consumed nonce.
6. Attacker resubmits `TX_old`. `verify_nonce` (`verifier.rs:211-221`) only checks `tx_nonce > current_nonce`; since `n_old > (M-1)*1e6`, the check passes and `TX_old` is re-executed, duplicating its effect (e.g., a repeated transfer) without the victim's renewed authorization.

### Citations

**File:** runtime/runtime/src/verifier.rs (L210-221)
```rust
/// Verify that the transaction nonce is valid.
fn verify_nonce(
    tx_nonce: Nonce,
    current_nonce: Nonce,
    block_height: Option<BlockHeight>,
    nonce_mode: NonceMode,
) -> Result<(), InvalidTxError> {
    match nonce_mode {
        NonceMode::Monotonic => {
            if tx_nonce <= current_nonce {
                return Err(InvalidTxError::InvalidNonce { tx_nonce, ak_nonce: current_nonce });
            }
```

**File:** runtime/runtime/src/access_keys.rs (L46-50)
```rust
pub(crate) fn initial_nonce_value(block_height: BlockHeight) -> Nonce {
    // Set default nonce for newly created access key to avoid transaction hash collision.
    // See <https://github.com/near/nearcore/issues/3779>.
    (block_height - 1) * near_primitives::account::AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER
}
```

**File:** runtime/runtime/src/access_keys.rs (L136-147)
```rust
fn delete_regular_key(
    fee_config: &RuntimeFeesConfig,
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    public_key: &PublicKey,
    access_key: &AccessKey,
) {
    let storage_usage = access_key_storage_usage(fee_config, public_key, access_key);
    remove_access_key(state_update, account_id.clone(), public_key.clone());
    account.set_storage_usage(account.storage_usage().saturating_sub(storage_usage));
}
```

**File:** runtime/runtime/src/access_keys.rs (L230-241)
```rust
fn add_regular_key(
    fee_config: &RuntimeFeesConfig,
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    public_key: &PublicKey,
    access_key: &AccessKey,
    block_height: BlockHeight,
) -> Result<(), StorageError> {
    let mut access_key = access_key.clone();
    access_key.nonce = initial_nonce_value(block_height);
    set_access_key(state_update, account_id.clone(), public_key.clone(), &access_key);
```

**File:** docs/DataStructures/AccessKey.md (L7-15)
```markdown
pub struct AccessKey {
    /// The nonce for this access key.
    /// NOTE: In some cases the access key needs to be recreated. If the new access key reuses the
    /// same public key, the nonce of the new access key should be equal to the nonce of the old
    /// access key. It's required to avoid replaying old transactions again.
    pub nonce: Nonce,
    /// Defines permissions for this access key.
    pub permission: AccessKeyPermission,
}
```
