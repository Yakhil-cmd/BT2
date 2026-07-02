The code trace confirms this is a real vulnerability. Let me walk through the exact mechanism.

**Architecture recap:**

- Key 0 is stored in the `apk_0` register (its `Revoked` field is embedded in the encoded key bytes).
- Keys ≥ 1 store their `revoked` bit in the key metadata section of the account status register, separately from the stored key material.
- When deduplication is active, key metadata for key 1 stores a `storedKeyIndex` mapping pointing back to `storedKeyIndex=0` (the `apk_0` register).

**Tracing the exploit step by step:**

**Step 1–2 (add key A at index 0, add duplicate at index 1):**
`AppendAccountPublicKeyMetadata` detects the duplicate via digest matching and calls `AppendDuplicateKeyMetadata(keyIndex=1, duplicateStoredKeyIndex=0, revoked=false, weight=...)`. The key metadata now records: key 1 → `storedKeyIndex=0`, `revoked=false`. The `deduplicated` flag is set in account status. [1](#0-0) 

**Step 3 (revoke index 0):**
`RevokeAccountPublicKey(addr, 0)` dispatches to `revokeAccountPublicKey0`, which reads `apk_0`, sets `Revoked=true`, and writes it back. It touches **only** the `apk_0` register. It does not scan key metadata for other logical indices that share `storedKeyIndex=0` and does not update their `revoked` bits. [2](#0-1) 

**Step 4 (`GetAccountPublicKey(addr, 1)`):**
`GetAccountPublicKey` for `keyIndex=1` calls `status.AccountPublicKeyMetadata(1)`, which reads the key metadata and returns `revoked=false` (key 1's own bit, never touched) and `storedKeyIndex=0`. It then calls `getStoredPublicKey(a, addr, 0)`, which reads `apk_0` but **only extracts `PublicKey`, `SignAlgo`, `HashAlgo`** — the `Revoked` field from `apk_0` is silently discarded. The returned `AccountPublicKey` has `Revoked: revoked` where `revoked` came from key metadata (false). [3](#0-2) [4](#0-3) 

**Step 5 (use index 1 as proposal key):**
`checkAndIncrementSequenceNumber` calls `GetAccountPublicKeyRevokedStatus(addr, 1)`, which calls `status.AccountPublicKeyRevokedStatus(1)` → `accountkeymetadata.GetRevokedStatus(keyMetadataBytes, 1)` → returns `false`. The revoked guard passes. [5](#0-4) 

`getAccountKeysAndAggregateWeights` calls `GetRuntimeAccountPublicKey(addr, 1)`, which follows the same path: `revoked` from key metadata = `false`, so `accountKey.Revoked` is `false` and the revoked check at line 305 passes. The transaction is accepted. [6](#0-5) 

---

### Title
Revoking a logical key index does not revoke co-mapped duplicate logical indices sharing the same stored key material — (`fvm/environment/accounts.go`, `fvm/environment/account_public_key_util.go`)

### Summary
When key deduplication is active, revoking logical key index 0 only sets the `Revoked` flag in the `apk_0` register. Any other logical key index (e.g., index 1) whose `storedKeyIndex` mapping points to `storedKeyIndex=0` retains its own independent `revoked=false` bit in key metadata. The `getStoredPublicKey` helper discards the `Revoked` field from `apk_0` when resolving stored key material. As a result, a transaction signed with the shared private key and submitted under the surviving logical index 1 passes all revocation checks and is accepted by the FVM.

### Finding Description
The revocation path for key index 0 (`revokeAccountPublicKey0`) and for key indices ≥ 1 (`AccountStatus.RevokeAccountPublicKey`) both operate on a single logical index at a time. Neither path inspects the key metadata to find other logical indices whose `storedKeyIndex` mapping resolves to the same stored key, and neither propagates the revocation to those indices.

The `getStoredPublicKey` function, when called with `storedKeyIndex=0`, reads `apk_0` and constructs a `StoredPublicKey` containing only `{PublicKey, SignAlgo, HashAlgo}`, explicitly dropping the `Revoked` field: [7](#0-6) 

The `revoked` value returned to callers of `GetAccountPublicKey` and `GetRuntimeAccountPublicKey` for key index 1 therefore comes exclusively from the key metadata entry for key 1, which was never updated: [8](#0-7) 

### Impact Explanation
In a multi-signer account (or any account where add-key and revoke-key operations are performed by different parties), a signer who adds a duplicate key at index 1 before their original key at index 0 is revoked retains full signing capability via index 1. The revocation of index 0 is silently ineffective against the shared key material. The surviving index passes both the proposal-key revocation check in `transactionSequenceNum.go` and the signature-level revocation check in `transactionVerifier.go`, allowing unauthorized use of key material that was intended to be revoked.

### Likelihood Explanation
Requires the attacker to have had prior add-key authorization on the account (i.e., they were a legitimate signer at some point). The attack is most relevant in multi-sig governance accounts where one party is being removed. It is concretely testable on an unmodified Flow emulator with no special privileges beyond normal transaction submission.

### Recommendation
`RevokeAccountPublicKey` (and `revokeAccountPublicKey0`) should, after revoking the target logical index, scan the key metadata for all other logical indices whose resolved `storedKeyIndex` equals the revoked key's `storedKeyIndex`, and set their `revoked` bits as well. Alternatively, the `getStoredPublicKey` helper for `storedKeyIndex=0` should propagate the `Revoked` field from `apk_0` upward, and callers should OR it with the logical-index revoked bit.

### Proof of Concept
```
1. Create account with key A at index 0 (storedKeyIndex=0).
2. Add duplicate key A at index 1 (AppendDuplicateKeyMetadata → storedKeyIndex=0, revoked=false in metadata).
3. RevokeAccountPublicKey(addr, 0) → sets Revoked=true in apk_0 only.
4. Assert GetAccountPublicKeyRevokedStatus(addr, 0) == true  ✓
5. Assert GetAccountPublicKeyRevokedStatus(addr, 1) == false  ← invariant broken
6. Submit transaction with ProposalKey{addr, keyIndex=1, seqNum=0}, signed with private key A.
7. checkAndIncrementSequenceNumber: revoked check for index 1 → false → passes.
8. getAccountKeysAndAggregateWeights: GetRuntimeAccountPublicKey(addr,1).Revoked == false → passes.
9. verifySignatures: signature verifies against stored key material (key A) → passes.
10. Transaction is accepted despite key A having been revoked at index 0.
```

### Citations

**File:** fvm/environment/accounts_status.go (L307-313)
```go
	if isDuplicateKey {
		err = keyMetadata.AppendDuplicateKeyMetadata(keyIndex, duplicateStoredKeyIndex, revoked, weight)
		if err != nil {
			return nil, 0, false, err
		}

		return keyMetadata, duplicateStoredKeyIndex, false, nil
```

**File:** fvm/environment/account_public_key_util.go (L79-117)
```go
func revokeAccountPublicKey0(
	a Accounts,
	address flow.Address,
) error {
	accountPublicKey0RegisterID := flow.AccountPublicKey0RegisterID(address)

	publicKey, err := a.GetValue(accountPublicKey0RegisterID)
	if err != nil {
		return err
	}

	const keyIndex = uint32(0)

	if len(publicKey) == 0 {
		return errors.NewAccountPublicKeyNotFoundError(
			address,
			keyIndex)
	}

	decodedPublicKey, err := flow.DecodeAccountPublicKey(publicKey, keyIndex)
	if err != nil {
		return fmt.Errorf(
			"failed to decode account public key 0: %w",
			err)
	}

	decodedPublicKey.Revoked = true

	encodedPublicKey, err := flow.EncodeAccountPublicKey(decodedPublicKey)
	if err != nil {
		encoded, _ := decodedPublicKey.MarshalJSON()
		return errors.NewValueErrorf(
			string(encoded),
			"failed to encode revoked account public key 0: %w",
			err)
	}

	return a.SetValue(accountPublicKey0RegisterID, encodedPublicKey)
}
```

**File:** fvm/environment/account_public_key_util.go (L198-216)
```go
func getStoredPublicKey(
	a Accounts,
	address flow.Address,
	storedKeyIndex uint32,
) (flow.StoredPublicKey, error) {
	if storedKeyIndex == 0 {
		// Stored key 0 is always account public key 0.

		accountKey, err := getAccountPublicKey0(a, address)
		if err != nil {
			return flow.StoredPublicKey{}, err
		}

		return flow.StoredPublicKey{
			PublicKey: accountKey.PublicKey,
			SignAlgo:  accountKey.SignAlgo,
			HashAlgo:  accountKey.HashAlgo,
		}, nil
	}
```

**File:** fvm/environment/accounts.go (L257-283)
```go
	// Get account public key metadata.
	weight, revoked, storedKeyIndex, err := status.AccountPublicKeyMetadata(keyIndex)
	if err != nil {
		return flow.AccountPublicKey{}, fmt.Errorf("failed to get account public key at index %d for %s: %w", keyIndex, address, err)
	}

	// Get stored public key.
	storedKey, err := getStoredPublicKey(a, address, storedKeyIndex)
	if err != nil {
		return flow.AccountPublicKey{}, fmt.Errorf("failed to get account public key at index %d for %s: %w", keyIndex, address, err)
	}

	// Get sequence number.
	sequenceNumber, err := getAccountPublicKeySequenceNumber(a, address, keyIndex)
	if err != nil {
		return flow.AccountPublicKey{}, fmt.Errorf("failed to get account public key at index %d for %s: %w", keyIndex, address, err)
	}

	return flow.AccountPublicKey{
		Index:     keyIndex,
		PublicKey: storedKey.PublicKey,
		SignAlgo:  storedKey.SignAlgo,
		HashAlgo:  storedKey.HashAlgo,
		SeqNumber: sequenceNumber,
		Weight:    int(weight),
		Revoked:   revoked,
	}, nil
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
