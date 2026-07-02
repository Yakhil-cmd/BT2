### Title
Digest Sliding-Window Eviction Allows Duplicate Key Re-Registration, Surviving Revocation — (`fvm/environment/account-key-metadata/metadata.go`)

### Summary

`FindDuplicateKey` only searches the last `MaxStoredDigests` (2) stored key digests. An attacker who controls an account can deliberately evict a key's digest from this window by adding two distinct unique keys, then re-add the same public key material as a new "unique" key with a fresh `storedKeyIndex`. Revoking the original key index only sets the revoked bit for that specific index; the re-registered copy at the new index remains active and fully usable for transaction signing.

### Finding Description

**Root cause — the sliding window in `appendDigest`:**

`appendDigest` maintains a fixed-size window of `MaxStoredDigests = 2` digests. [1](#0-0) [2](#0-1) 

When a third unique key is added, the oldest digest is dropped from the front and `startIndexForDigests` is incremented. The evicted digest is permanently gone from the searchable window.

**`FindDuplicateKey` / `findDuplicateDigest` only search the live window:** [3](#0-2) [4](#0-3) 

If a key's digest has been evicted, `FindDuplicateKey` returns `isDuplicateKey = false`, and `appendAccountPublicKeyMetadata` calls `AppendUniqueKeyMetadata`, assigning a brand-new `storedKeyIndex` and writing the key material to storage again (`saveKey = true`). [5](#0-4) 

**Revocation is per-`keyIndex`, not per-key-material:**

`RevokeAccountPublicKey` sets the revoked bit only for the specific `keyIndex` in `weightAndRevokedStatusBytes`. It has no knowledge of other key indices that share the same public key material. [6](#0-5) [7](#0-6) 

**Transaction verification checks revoked status by `keyIndex`:**

Both the sequence-number checker and the signature verifier call `GetRuntimeAccountPublicKey` / `GetAccountPublicKeyRevokedStatus` keyed on the `keyIndex` supplied in the transaction. If that index is not revoked, the transaction proceeds. [8](#0-7) [9](#0-8) 

### Impact Explanation

An attacker who has (or had) signing access to an account can pre-position a duplicate key that survives any future revocation of the original key index. After the account owner revokes the original index, the attacker retains full transaction-signing authority via the re-registered index, enabling unauthorized execution of arbitrary Cadence transactions under that account's authorization — including resource transfers, contract calls, and capability grants.

### Likelihood Explanation

The attack requires only 3 `addKey` Cadence transactions (all standard account operations) followed by re-adding the target key. No privileged node access, no hash collision, and no brute force is needed. The window size of 2 makes eviction trivially cheap. Any attacker with temporary account access (e.g., a compromised key that the owner later tries to revoke) can execute this before the revocation.

### Recommendation

1. **Cross-reference by stored key material on re-add:** Before treating a newly added key as unique, compare its encoded bytes against all existing non-revoked stored keys, not just the last-N digests. The digest window is an optimization for deduplication, not a security boundary.
2. **Alternatively, store a full digest history** (or a Bloom filter) so that evicted digests can still be matched, triggering a full byte-comparison fallback.
3. **At minimum, document and enforce** that `RevokeAccountPublicKey` must be understood as revoking a *key index*, not the underlying key material, and provide a `RevokeKeyMaterial` primitive that scans all indices sharing the same stored key.

### Proof of Concept

```
// Emulator localnet test (pseudocode)
account := createAccount()
K := generateKeyPair()
A := generateKeyPair()   // distinct
B := generateKeyPair()   // distinct

addKey(account, K)  // keyIndex=0, storedKeyIndex=0; window=[digest(K)]
addKey(account, A)  // keyIndex=1, storedKeyIndex=1; window=[digest(K), digest(A)]
addKey(account, B)  // keyIndex=2, storedKeyIndex=2; window=[digest(A), digest(B)]  ← K evicted

// Re-add K: FindDuplicateKey searches [digest(A),digest(B)], misses K → treated as unique
addKey(account, K)  // keyIndex=3, storedKeyIndex=3, saveKey=true; window=[digest(B), digest(K)]

assert storedKeyIndex(3) != storedKeyIndex(0)  // 3 != 0 ✓

revokeKey(account, keyIndex=0)  // sets revoked bit for index 0 only

// Submit tx signed with key material K, proposalKey.KeyIndex=3
tx := buildTx(proposalKeyIndex=3)
tx.sign(K)
result := submitTx(tx)
assert result.Error == nil  // succeeds — K is still active at index 3
```

The `GetRuntimeAccountPublicKey(address, 3)` call returns `revoked=false` and the public key bytes of K; the cryptographic signature verifies; the transaction executes successfully despite the owner having revoked K at index 0. [10](#0-9) [2](#0-1) [11](#0-10) [9](#0-8)

### Citations

**File:** fvm/environment/accounts_status.go (L40-41)
```go
	MaxStoredDigests = 2 // Account status register stores up to 2 digests from last 2 stored keys.
)
```

**File:** fvm/environment/accounts_status.go (L184-192)
```go
func (a *AccountStatus) RevokeAccountPublicKey(keyIndex uint32) error {
	var err error
	a.keyMetadataBytes, err = accountkeymetadata.SetRevokedStatus(a.keyMetadataBytes, keyIndex)
	if err != nil {
		return err
	}

	return nil
}
```

**File:** fvm/environment/accounts_status.go (L287-323)
```go
	digest, isDuplicateKey, duplicateStoredKeyIndex, err := accountkeymetadata.FindDuplicateKey(keyMetadata, encodedKey, getKeyDigest, getStoredKey)
	if err != nil {
		return nil, 0, false, err
	}

	// Whether new public key is a duplicate or not, we store these items in key metadata section:
	// - new account public key's revoked status and weight
	// - new public key's digest (we only store last N digests and N=2 by default to balance tradeoffs)
	// If new public key is a duplicate, we also store mapping of account key index to stored key index.
	//
	// As a non-duplicate key example, if public key at index 1 is unique, we store:
	// - new key's weight and revoked status, and
	// - new key's digest
	//
	// As a duplicate key example, if public key at index 1 is duplicate of public key at index 0, we store:
	// - new key's weight and revoked status,
	// - mapping indicating public key at index 1 is the same as public key at index 0.
	// - new key's digest

	// Handle duplicate key.
	if isDuplicateKey {
		err = keyMetadata.AppendDuplicateKeyMetadata(keyIndex, duplicateStoredKeyIndex, revoked, weight)
		if err != nil {
			return nil, 0, false, err
		}

		return keyMetadata, duplicateStoredKeyIndex, false, nil
	}

	// Handle non-duplicate key.
	storedKeyIndex, err = keyMetadata.AppendUniqueKeyMetadata(revoked, weight, digest)
	if err != nil {
		return nil, 0, false, err
	}

	return keyMetadata, storedKeyIndex, true, nil
}
```

**File:** fvm/environment/account-key-metadata/metadata.go (L267-283)
```go
func (m *KeyMetadataAppender) appendDigest(digest uint64) {
	digestCount := 1 + len(m.digestBytes)/digestSize

	if digestCount > int(m.maxStoredDigests) {
		// Remove digest from front
		removeCount := digestCount - int(m.maxStoredDigests)
		m.digestBytes = slices.Delete(m.digestBytes, 0, removeCount*digestSize)

		// Adjust digest start index
		m.startIndexForDigests += uint32(removeCount)
	}

	var digestBytes [digestSize]byte
	binary.BigEndian.PutUint64(digestBytes[:], digest)

	m.digestBytes = append(m.digestBytes, digestBytes[:]...)
}
```

**File:** fvm/environment/account-key-metadata/metadata.go (L349-366)
```go
// findDuplicateDigest returns true and stored key index with duplicate digest
// if the given digest has a match in stored digests in key metadata section.
func (m *KeyMetadataAppender) findDuplicateDigest(digest uint64) (found bool, duplicateStoredKeyIndex uint32) {
	if len(m.digestBytes) == 0 {
		return false, 0
	}

	var digestBytes [digestSize]byte
	binary.BigEndian.PutUint64(digestBytes[:], digest)

	for off, i := 0, uint32(0); off < len(m.digestBytes); off, i = off+digestSize, i+1 {
		if bytes.Equal(digestBytes[:], m.digestBytes[off:off+digestSize]) {
			return true, m.startIndexForDigests + i
		}
	}

	return false, 0
}
```

**File:** fvm/environment/account-key-metadata/digest.go (L13-52)
```go
// FindDuplicateKey returns true with duplicate key index if duplicate key
// of the given key is found.  However, detection rate is intentionally
// not 100% in order to limit the number of digests we store on chain.
// If a hash collision happens with given digest, this function returns
// SentinelFastDigest64 digest and duplicate key not found.
// Specifically, a duplicate key is found when these conditions are met:
// - computed digest isn't the predefined sentinel digest (0),
// - computed digest matches one of the stored digests in key metadata, and
// - given encodedKey also matches the stored key with the same digest.
func FindDuplicateKey(
	keyMetadata *KeyMetadataAppender,
	encodedKey []byte,
	getKeyDigest func([]byte) uint64,
	getStoredKey func(uint32) ([]byte, error),
) (digest uint64, found bool, duplicateStoredKeyIndex uint32, _ error) {

	// To balance tradeoffs, it is OK to have detection rate less than 100%, for the
	// same reasons compression programs/libraries don't use max compression by default.

	// We use a fast non-cryptographic hash algorithm for efficiency, so
	// we need to handle hash collisions (same digest from different hash inputs).
	// When a hash collision is detected, sentinel digest (0) is stored in place
	// of new key digest, and subsequent digest comparison excludes stored sentinel digest.
	// This means keys with the sentinel digest will not be deduplicated and that is OK.

	digest = getKeyDigest(encodedKey)

	if digest == SentinelFastDigest64 {
		// The new key digest matches the sentinel digest by coincidence or attack.
		// Return early so the key will be stored without using deduplication.
		return SentinelFastDigest64, false, 0, nil
	}

	// Find duplicate stored digest by comparing computed digest against stored digests in key metadata section.
	found, duplicateStoredKeyIndex = keyMetadata.findDuplicateDigest(digest)

	// If no duplicate digest is found, we return duplicate not found.
	if !found {
		return digest, false, 0, nil
	}
```

**File:** fvm/environment/accounts.go (L362-386)
```go
func (a *StatefulAccounts) RevokeAccountPublicKey(
	address flow.Address,
	keyIndex uint32,
) error {
	err := a.accountPublicKeyIndexInRange(address, keyIndex)
	if err != nil {
		return err
	}

	if keyIndex == 0 {
		return revokeAccountPublicKey0(a, address)
	}

	status, err := a.getAccountStatus(address)
	if err != nil {
		return err
	}

	err = status.RevokeAccountPublicKey(keyIndex)
	if err != nil {
		return fmt.Errorf("failed to revoke public key at index %d for %s: %w", keyIndex, address, err)
	}

	return a.setAccountStatusAfterAccountStatusSizeChange(address, status)
}
```

**File:** fvm/transactionSequenceNum.go (L56-65)
```go
	revoked, err := accounts.GetAccountPublicKeyRevokedStatus(proposalKey.Address, proposalKey.KeyIndex)
	if err != nil {
		return errors.NewInvalidProposalSignatureError(proposalKey, err)
	}

	if revoked {
		return errors.NewInvalidProposalSignatureError(
			proposalKey,
			fmt.Errorf("proposal key has been revoked"))
	}
```

**File:** fvm/transactionVerifier.go (L297-308)
```go
	for _, signature := range signatures {
		accountKey, err := accounts.GetRuntimeAccountPublicKey(
			signature.Address,
			signature.KeyIndex)
		if err != nil {
			return signature.newError(err)
		}

		if accountKey.Revoked {
			return signature.newError(
				fmt.Errorf("account key has been revoked"))
		}
```
