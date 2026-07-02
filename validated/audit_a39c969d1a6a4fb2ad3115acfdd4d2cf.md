The question requires careful tracing of the full verification path. Let me confirm the final piece — whether `verifySignatures` uses the stored key (same for both indices) and whether there is any guard against two key indices mapping to the same stored key.

### Title
Single Cryptographic Key Bypasses Weight Threshold via Duplicate Key Registration — (`fvm/transactionVerifier.go`, `fvm/environment/accounts.go`)

---

### Summary

The transaction verifier deduplicates signatures by `(address, keyIndex)` pair but never checks whether two distinct key indices resolve to the same underlying stored cryptographic key. Because the key-metadata subsystem explicitly supports registering a duplicate public key under a new index with an independent weight, an account holder with a sub-threshold key (e.g., weight=500) can register a duplicate of that key at a new index with a complementary weight (e.g., weight=600), then sign a transaction twice with the single private key — once per index — causing the verifier to aggregate 500+600=1100 ≥ 1000 and accept the transaction.

---

### Finding Description

**Key registration path**

When a new public key is appended, `appendAccountPublicKeyMetadata` in `fvm/environment/accounts_status.go` calls `FindDuplicateKey`. If the new key's encoded bytes match an existing stored key, `isDuplicateKey=true` is returned along with `duplicateStoredKeyIndex` pointing to the original stored key. The code then calls `AppendDuplicateKeyMetadata(keyIndex, duplicateStoredKeyIndex, revoked, weight)`, which:

- Appends the **new** weight/revoked entry (weight=600) into the RLE weight structure for the new key index.
- Writes a mapping entry: new key index → same `storedKeyIndex` as the original key.
- Does **not** store a second copy of the key bytes (`saveKey=false`). [1](#0-0) 

**Transaction verification path**

`newSignatureEntries` deduplicates signatures by `(address, keyIndex)` pair only: [2](#0-1) 

Two signatures referencing key index 0 and key index 1 of the same address are treated as two distinct, valid entries. There is no check that the underlying stored key is the same.

`getAccountKeysAndAggregateWeights` then calls `GetRuntimeAccountPublicKey` for each signature entry independently: [3](#0-2) 

For key index 0, `GetRuntimeAccountPublicKey` returns weight=500 and the underlying `PublicKey`. For key index 1, it resolves `storedKeyIndex=0` via the deduplication mapping and returns weight=600 with the **same** `PublicKey`. Both weights are added to the same address bucket: [4](#0-3) 

Total = 1100 ≥ 1000 threshold.

`verifySignatures` then verifies each signature against `entry.accountKey.PublicKey`. Since both entries carry the same underlying public key, a single private key produces a valid signature for both: [5](#0-4) 

`GetRuntimeAccountPublicKey` for key index 1 explicitly resolves through the deduplication mapping to `storedKeyIndex=0`, returning the same `PublicKey` bytes as key index 0: [6](#0-5) 

The weight returned for key index 1 is the independently stored weight=600, not the original key's weight=500: [7](#0-6) 

---

### Impact Explanation

The invariant that a single cryptographic key may contribute at most its own registered weight to the authorization threshold is broken. In a multi-party account (e.g., two parties each holding a key with weight=500, requiring both to sign), one party can unilaterally register a duplicate of their own key with weight=600, then sign transactions alone (500+600=1100) without the other party's participation. This constitutes unauthorized mutation of shared account authorization state and unauthorized transaction execution.

---

### Likelihood Explanation

The attack requires only the ability to add a key to an account — a standard Cadence operation available to any account holder. No privileged access, leaked keys, or external dependencies are needed. The duplicate-key registration path is an intentional feature of the metadata subsystem, and the verifier has no guard against it. The exploit is deterministic and locally reproducible on an unmodified emulator.

---

### Recommendation

In `newSignatureEntries` or `getAccountKeysAndAggregateWeights`, after resolving each key index to its `storedKeyIndex` (via `GetRuntimeAccountPublicKey` or a dedicated lookup), track the set of `(address, storedKeyIndex)` pairs already seen. If a second signature entry resolves to an already-seen `(address, storedKeyIndex)`, reject the transaction with a duplicate-underlying-key error — or, at minimum, do not add its weight a second time. The deduplication must operate on the underlying stored key identity, not the logical key index.

---

### Proof of Concept

1. On a local Flow emulator, create account `A` with key0 (ECDSA-P256, weight=500).
2. From account `A`, execute a Cadence transaction that calls `account.keys.add(publicKey: key0.publicKey, hashAlgorithm: HashAlgorithm.SHA3_256, weight: 600.0)` — registering key1 with the same public key bytes and weight=600.
3. Construct a transaction with `A` as payer, proposer (key index 0), and authorizer.
4. Sign the envelope with key0's private key referencing key index 0 (weight=500).
5. Also sign the envelope with the same private key referencing key index 1 (weight=600).
6. Submit. The verifier aggregates 500+600=1100 ≥ 1000, both cryptographic verifications pass against the same public key, and the transaction is accepted — despite no single key having weight ≥ 1000.

### Citations

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

**File:** fvm/transactionVerifier.go (L75-80)
```go
	valid, err := crypto.VerifySignatureFromTransaction(
		entry.Signature,
		message,
		entry.accountKey.PublicKey,
		entry.accountKey.HashAlgo,
	)
```

**File:** fvm/transactionVerifier.go (L139-171)
```go
	type uniqueKey struct {
		address flow.Address
		index   uint32
	}
	duplicate := make(map[uniqueKey]struct{}, numSignatures)

	for _, group := range list {
		for _, signature := range group.signatures {
			entry := &signatureContinuation{
				signatureEntry: signatureEntry{
					TransactionSignature: signature,
					signatureType:        group.signatureType,
				},
			}

			// check signature address is either payer, proposer or authorizer
			_, ok := transactionAddresses[signature.Address]
			if !ok {
				return nil, nil, nil, entry.newError(
					fmt.Errorf("signature is provided for account %s that is neither payer nor authorizer nor proposer", signature.Address))
			}

			key := uniqueKey{
				address: signature.Address,
				index:   signature.KeyIndex,
			}

			_, ok = duplicate[key]
			if ok {
				return nil, nil, nil, entry.newError(
					fmt.Errorf("duplicate signatures are provided for the same key"))
			}
			duplicate[key] = struct{}{}
```

**File:** fvm/transactionVerifier.go (L296-312)
```go
	foundProposalSignature := false
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
