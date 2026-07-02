The code trace is complete. Let me lay out the exact data-flow before rendering the verdict.

**Architecture recap:**

- Key-0 is stored in a dedicated `apk_0` register; its `Revoked` bit lives inside that register.
- Keys 1+ have their metadata (weight, `revoked`, `storedKeyIndex`) stored in the `keyMetadataBytes` section of the `AccountStatus` register — one entry per *logical* key index, independent of whether two logical keys share the same stored key bytes.

**Trace of the proposed attack:**

1. **Add duplicate key-1.** `AppendAccountPublicKey` → `appendPublicKey` → `appendKeyMetadataToAccountStatusRegister` → `AppendAccountPublicKeyMetadata`. `FindDuplicateKey` detects key-1 is identical to key-0 and calls `AppendDuplicateKeyMetadata(keyIndex=1, duplicateStoredKeyIndex=0, revoked=false, weight=...)`. This writes key-1's own `revoked=false` bit into `keyMetadataBytes` and a mapping `1→storedKeyIndex=0`. The `apk_0` register is untouched. [1](#0-0) [2](#0-1) 

2. **Revoke key-0.** `RevokeAccountPublicKey(addr, 0)` branches on `keyIndex == 0` and calls `revokeAccountPublicKey0`, which reads `apk_0`, sets `decodedPublicKey.Revoked = true`, and writes back to `apk_0`. The `keyMetadataBytes` in `AccountStatus` — where key-1's independent `revoked` bit lives — is **never touched**. [3](#0-2) [4](#0-3) 

3. **Read key-1 after revocation.** `GetRuntimeAccountPublicKey(addr, 1)` calls `status.AccountPublicKeyMetadata(1)` → `accountkeymetadata.GetKeyMetadata(keyMetadataBytes, 1, deduplicated=true)`. This returns `revoked=false` (key-1's own bit) and `storedKeyIndex=0` (the mapping). The `apk_0` register is never consulted for key-1's revoked status. [5](#0-4) [6](#0-5) 

4. **Transaction verifier.** `getAccountKeysAndAggregateWeights` calls `GetRuntimeAccountPublicKey(addr, 1)`, receives `Revoked: false`, and does not reject the signature. [7](#0-6) 

5. **Sequence-number checker.** `checkAndIncrementSequenceNumber` calls `GetAccountPublicKeyRevokedStatus(addr, 1)` → `status.AccountPublicKeyRevokedStatus(1)` → `GetRevokedStatus(keyMetadataBytes, 1)`, which again reads key-1's own bit (`false`). The revocation check passes. [8](#0-7) [9](#0-8) 

The existing test suite confirms the design: each logical key index has its own independent `revoked` bit even for duplicate keys, and revoking one index never propagates to another. [10](#0-9) 

---

### Title
Key-revocation bypass via duplicate-key alias — revoking key-0 leaves key-1 (a duplicate) fully operational - (`fvm/environment/accounts.go`)

### Summary
When a duplicate key is appended (key-1 shares key material with key-0), each logical key index stores its own independent `revoked` bit in `keyMetadataBytes`. Revoking key-0 only updates the `apk_0` register; key-1's `revoked` bit in `keyMetadataBytes` remains `false`. Both the transaction verifier and the sequence-number checker read the revoked status from the per-logical-index metadata, so a transaction signed with the shared key material and `proposerKeyIndex=1` is accepted even after key-0 is revoked.

### Finding Description
`RevokeAccountPublicKey(addr, 0)` calls `revokeAccountPublicKey0`, which exclusively modifies the `apk_0` register. [11](#0-10) 

`RevokeAccountPublicKey(addr, N>0)` calls `status.RevokeAccountPublicKey(N)` → `accountkeymetadata.SetRevokedStatus(keyMetadataBytes, N)`, which sets only the bit for index N in the weight-and-revoked-status section. [12](#0-11) 

Neither path propagates the revocation to other logical key indices that share the same `storedKeyIndex`. The `storedKeyIndex` mapping is a read-only indirection for key-material lookup; it plays no role in revocation. [13](#0-12) 

### Impact Explanation
An attacker who previously held (or still holds) the private key for key-0 and who added key-1 as a duplicate retains full signing authority after the account owner revokes key-0. Any transaction with `proposerKeyIndex=1` (or any signature using key-index=1) passes both the revocation check and the cryptographic verification, because the stored key material is identical and the `revoked` flag for index 1 is `false`.

### Likelihood Explanation
Requires the attacker to have had temporary authorization on the account (to call `addAccountKey`). Once key-1 is planted, the attack is persistent and survives any number of key-0 revocations. The account owner has no obvious signal that key-1 is a duplicate of key-0 unless they explicitly compare key bytes.

### Recommendation
When revoking a key at index N, iterate over all logical key indices whose `storedKeyIndex` equals the `storedKeyIndex` of N and set their `revoked` bits as well. Alternatively, store the `revoked` bit on the *stored key* rather than on the logical key index, so that revoking any alias automatically revokes all aliases.

### Proof of Concept
```
1. Create account A with key-0 (weight 1000).
2. addAccountKey(A, key-0.publicKey, weight=1) → key-1 is registered as a duplicate; storedKeyIndex=0.
3. revokeAccountKey(A, 0) → apk_0.Revoked = true; keyMetadataBytes[1].revoked remains false.
4. getAccountKey(A, 1).isRevoked → false   ← invariant broken
5. Submit transaction: proposer=(A, keyIndex=1, seqNum=0), signed with key-0 private key.
   → TransactionSequenceNumberChecker: GetAccountPublicKeyRevokedStatus(A,1) = false → passes
   → TransactionVerifier: GetRuntimeAccountPublicKey(A,1).Revoked = false → passes
   → Cryptographic verification: succeeds (same key material)
   → Transaction accepted.
``` [14](#0-13) [15](#0-14) [8](#0-7)

### Citations

**File:** fvm/environment/accounts_status.go (L165-169)
```go
// AccountPublicKeyRevokedStatus returns revoked status of account public key at the given key index stored in key metadata.
// NOTE: To avoid checking keyIndex range repeatedly at different levels, caller must ensure keyIndex > 0 and < AccountPublicKeyCount().
func (a *AccountStatus) AccountPublicKeyRevokedStatus(keyIndex uint32) (bool, error) {
	return accountkeymetadata.GetRevokedStatus(a.keyMetadataBytes, keyIndex)
}
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

**File:** fvm/environment/accounts_status.go (L306-313)
```go
	// Handle duplicate key.
	if isDuplicateKey {
		err = keyMetadata.AppendDuplicateKeyMetadata(keyIndex, duplicateStoredKeyIndex, revoked, weight)
		if err != nil {
			return nil, 0, false, err
		}

		return keyMetadata, duplicateStoredKeyIndex, false, nil
```

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

**File:** fvm/environment/account-key-metadata/metadata.go (L314-343)
```go
// AppendDuplicateKeyMetadata appends duplicate key metadata.
func (m *KeyMetadataAppender) AppendDuplicateKeyMetadata(
	keyIndex uint32,
	duplicateStoredKeyIndex uint32,
	revoked bool,
	weight uint16,
) (err error) {

	// Append revoked status and weight
	m.weightAndRevokedStatusBytes, err = appendWeightAndRevokedStatus(m.weightAndRevokedStatusBytes, revoked, weight)
	if err != nil {
		return err
	}

	if !m.deduplicated {
		// Set deduplication flag
		m.deduplicated = true

		// Save mapping start key index.
		m.startIndexForMapping = keyIndex
	}

	// Append duplicate stored key index to mapping
	m.mappingBytes, err = appendStoredKeyIndexToMappings(m.mappingBytes, duplicateStoredKeyIndex)
	if err != nil {
		return err
	}

	return nil
}
```

**File:** fvm/environment/accounts.go (L258-283)
```go
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

**File:** fvm/transactionVerifier.go (L297-317)
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

		if !foundProposalSignature && signature.matches(proposalKey) {
			foundProposalSignature = true
		}
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

**File:** fvm/environment/accounts_test.go (L1275-1315)
```go
	t.Run("account with 2 duplicate key", func(t *testing.T) {
		key0 := newAccountPublicKey(t, 1000)
		key1 := key0
		key1.Weight = 1
		keys := []flow.AccountPublicKey{key0, key1}

		txnState := testutils.NewSimpleTransaction(nil)
		accounts := environment.NewAccounts(txnState)

		address := flow.HexToAddress("01")

		err := accounts.Create(nil, address)
		require.NoError(t, err)

		for _, key := range keys {
			err = accounts.AppendAccountPublicKey(address, key)
			require.NoError(t, err)
		}

		keyCount, err := accounts.GetAccountPublicKeyCount(address)
		require.NoError(t, err)
		require.Equal(t, uint32(len(keys)), keyCount)

		for i, key := range keys {
			revoked, err := accounts.GetAccountPublicKeyRevokedStatus(address, uint32(i))
			require.NoError(t, err)
			require.False(t, revoked)

			err = accounts.RevokeAccountPublicKey(address, uint32(i))
			require.NoError(t, err)

			revoked, err = accounts.GetAccountPublicKeyRevokedStatus(address, uint32(i))
			require.NoError(t, err)
			require.True(t, revoked)

			retrievedKey, err := accounts.GetAccountPublicKey(address, uint32(i))
			require.NoError(t, err)
			key.Index = uint32(i)
			key.Revoked = true
			require.Equal(t, key, retrievedKey)
		}
```
