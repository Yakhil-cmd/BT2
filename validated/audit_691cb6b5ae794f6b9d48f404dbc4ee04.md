The key question is whether `SetRevokedStatus` for keyIndex=1 leaves keyIndex=2 (a duplicate) unrevoked, and whether the transaction verifier then accepts a signature from key index 2. Let me verify the exact data flow.

The data flow is now fully traced. The vulnerability is real and concrete.

**Data flow summary:**

1. `SetRevokedStatus(b, keyIndex=1)` sets the revoked bit only in the weight/revoked section at position `keyIndex-1=0` (0-indexed). It has no knowledge of, and makes no change to, the revoked bit for keyIndex=2. [1](#0-0) 

2. `GetKeyMetadata(b, keyIndex=2, deduplicated=true)` reads `revoked` from the weight/revoked section at position `keyIndex-1=1` (0-indexed) — which is the per-index revoked bit for index 2, untouched by the revocation of index 1. It then separately reads `storedKeyIndex=1` from the mapping section (pointing to K's bytes). [2](#0-1) 

3. `GetRuntimeAccountPublicKey(addr, 2)` assembles the result: `Revoked: false` (from the per-index bit for index 2) and `PublicKey: K` (from storedKeyIndex=1). The revoked status is sourced from the per-keyIndex metadata, not from the stored key. [3](#0-2) 

4. `getAccountKeysAndAggregateWeights` checks `accountKey.Revoked` — which is `false` for key index 2 — and proceeds without error. Signature verification then succeeds because the public key bytes match the signature produced by the same private key. [4](#0-3) 

5. `checkAndIncrementSequenceNumber` also checks revoked status per-keyIndex (for the proposal key), and key index 2 is not revoked, so it passes too. [5](#0-4) 

---

### Title
Per-Index Revocation Does Not Revoke Signing Authority of Duplicate Keys — (`fvm/environment/account-key-metadata/metadata.go`)

### Summary
Revoking an account key by index only clears the revoked bit for that specific index in the weight/revoked metadata section. If the same cryptographic key material was added at a second index (deduplication stores a mapping to the same `storedKeyIndex`), the second index retains `Revoked: false` and its full signing weight. An attacker who previously added a duplicate of a key can continue signing transactions after the account owner revokes the original index.

### Finding Description
The key metadata format stores a per-index `(weight, revoked)` tuple for every account key index ≥ 1, plus a mapping from key index to `storedKeyIndex` for deduplicated keys. `SetRevokedStatus` operates exclusively on the weight/revoked section, setting the revoked bit only for the targeted `keyIndex`. It does not inspect the mapping section and does not propagate the revocation to any other index that shares the same `storedKeyIndex`.

When `GetRuntimeAccountPublicKey` is called for a duplicate key index, it reads:
- `revoked` from the per-index weight/revoked section (not revoked for the duplicate index)
- `storedKeyIndex` from the mapping section (pointing to the same stored key bytes as the revoked index)

The returned `RuntimeAccountPublicKey` has `Revoked: false` and the original public key bytes. The transaction verifier accepts this key, and signature verification succeeds because the same private key produces a valid signature for both indices.

### Impact Explanation
An attacker who previously had account access (sufficient to add a duplicate key) can retain signing authority indefinitely after the account owner revokes the original key index. The attacker can submit authorized transactions, drain resources, modify account state, or perform any action the key's weight permits — all after the owner believes the key has been revoked.

### Likelihood Explanation
The attack requires the attacker to have previously held signing authority (to add the duplicate key). This is realistic in key-compromise recovery scenarios: the attacker steals a private key, adds a duplicate at a new index, and the owner revokes only the known index. The owner has no indication that a duplicate exists at another index unless they enumerate all keys.

### Recommendation
`SetRevokedStatus` (or its callers) must propagate revocation to all key indices that share the same `storedKeyIndex`. Concretely, when revoking keyIndex `i`, the system should scan the mapping section for all indices `j` where `storedKeyIndex(j) == storedKeyIndex(i)` and set their revoked bits as well. Alternatively, the revoked bit could be stored on the `storedKeyIndex` (i.e., on the stored key itself) rather than per logical index, so that revoking any alias revokes all aliases.

### Proof of Concept
```
// Setup: account with key K at index 0, duplicate K at index 1
// (storedKeyIndex=0 for both via deduplication mapping)

// Step 1: add K at index 0 (unique)
accounts.AppendAccountPublicKey(addr, keyK_weight1000)
// → storedKeyIndex=0, revoked=false

// Step 2: add K again at index 1 (duplicate)
accounts.AppendAccountPublicKey(addr, keyK_weight500)
// → storedKeyIndex=0 (mapping: index 1 → stored 0), revoked=false

// Step 3: owner revokes index 0
accounts.RevokeAccountPublicKey(addr, 0)
// → weight/revoked section for index 0: revoked=true
// → weight/revoked section for index 1: revoked=false  ← NOT touched

// Step 4: attacker queries key at index 1
key, _ := accounts.GetRuntimeAccountPublicKey(addr, 1)
// key.Revoked == false  ← bypass
// key.PublicKey == K    ← same bytes

// Step 5: attacker submits transaction with ProposalKey.KeyIndex=1,
//         signed with the private key for K
// → getAccountKeysAndAggregateWeights: accountKey.Revoked=false → passes
// → verifySignatures: signature valid against K → passes
// → transaction executes
``` [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** fvm/environment/account-key-metadata/metadata.go (L49-77)
```go
	// Get weight and revoked status for given account key index
	revoked, weight, err = getWeightAndRevokedStatus(weightAndRevokedStatusBytes, keyIndex-1)
	if err != nil {
		return 0, false, 0, err
	}

	// If keys are not deduplicated, storedKeyIndex is the same as the given keyIndex.
	if !deduplicated {
		return weight, revoked, keyIndex, nil
	}

	// Get raw key index mapping bytes
	startIndexForMapping, mappingBytes, _, err := parseStoredKeyMappingFromKeyMetadataBytes(rest)
	if err != nil {
		return 0, false, 0, err
	}

	// StoredKeyIndex is the same as the given keyIndex if deduplication happens afterwards.
	if keyIndex < startIndexForMapping {
		return weight, revoked, keyIndex, nil
	}

	// Get stored key index from mapping
	storedKeyIndex, err = getStoredKeyIndexFromMappings(mappingBytes, keyIndex-startIndexForMapping)
	if err != nil {
		return 0, false, 0, err
	}

	return weight, revoked, storedKeyIndex, nil
```

**File:** fvm/environment/account-key-metadata/metadata.go (L80-110)
```go
// SetRevokedStatus revokes key and returns encoded key metadata.
// NOTE: b may be modified.
func SetRevokedStatus(b []byte, keyIndex uint32) ([]byte, error) {
	// Key metadata only stores weight and revoked status for keys at index > 0.

	if keyIndex == 0 {
		return nil, errors.NewKeyMetadataUnexpectedKeyIndexError("failed to set revoked status", 0)
	}

	weightAndRevokedStatusBytes, rest, err := parseWeightAndRevokedStatusFromKeyMetadataBytes(b)
	if err != nil {
		return nil, err
	}

	newWeightAndRevokedStatusBytes, err := setRevokedStatus(slices.Clone(weightAndRevokedStatusBytes), keyIndex-1)
	if err != nil {
		return nil, err
	}

	newB := make([]byte, lengthPrefixSize+len(newWeightAndRevokedStatusBytes)+len(rest))
	off := 0

	binary.BigEndian.PutUint32(newB, uint32(len(newWeightAndRevokedStatusBytes)))
	off += 4

	n := copy(newB[off:], newWeightAndRevokedStatusBytes)
	off += n

	copy(newB[off:], rest)
	return newB, nil
}
```

**File:** fvm/environment/accounts.go (L318-337)
```go
	// Get account public key metadata.
	weight, revoked, storedKeyIndex, err := status.AccountPublicKeyMetadata(keyIndex)
	if err != nil {
		return flow.RuntimeAccountPublicKey{}, fmt.Errorf("failed to get account public key at index %d for %s: %w", keyIndex, address, err)
	}

	// Get stored public key.
	storedKey, err := getStoredPublicKey(a, address, storedKeyIndex)
	if err != nil {
		return flow.RuntimeAccountPublicKey{}, fmt.Errorf("failed to get account public key at index %d for %s: %w", keyIndex, address, err)
	}

	return flow.RuntimeAccountPublicKey{
		Index:     keyIndex,
		PublicKey: storedKey.PublicKey,
		SignAlgo:  storedKey.SignAlgo,
		HashAlgo:  storedKey.HashAlgo,
		Weight:    int(weight),
		Revoked:   revoked,
	}, nil
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

**File:** fvm/transactionVerifier.go (L297-312)
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

		signature.accountKey = accountKey
		// aggregateWeight
		signature.aggregateWeights[signature.Address] += accountKey.Weight
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

**File:** fvm/environment/accounts_status.go (L182-192)
```go
// RevokeAccountPublicKey revokes account public key at the given key index stored in key metadata.
// NOTE: To avoid checking keyIndex range repeatedly at different levels, caller must ensure keyIndex > 0 and < AccountPublicKeyCount().
func (a *AccountStatus) RevokeAccountPublicKey(keyIndex uint32) error {
	var err error
	a.keyMetadataBytes, err = accountkeymetadata.SetRevokedStatus(a.keyMetadataBytes, keyIndex)
	if err != nil {
		return err
	}

	return nil
}
```
