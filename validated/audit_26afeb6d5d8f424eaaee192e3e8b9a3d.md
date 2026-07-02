The vulnerability is confirmed. Here is the complete trace:

**Root cause chain:**

1. `revokeAccountPublicKey0()` only writes `Revoked=true` into the `apk_0` register. It never touches `keyMetadataBytes`. [1](#0-0) 

2. `getStoredPublicKey(a, address, storedKeyIndex=0)` reads from `apk_0` but returns a `StoredPublicKey` — a type that has **no `Revoked` field** — so the revoked status from `apk_0` is silently discarded. [2](#0-1) 

3. `GetRuntimeAccountPublicKey(addr, 1)` assembles the returned struct using `revoked` from `AccountPublicKeyMetadata(1)` (the per-index bit in `keyMetadataBytes` for key 1, which was never set to `true`), not from the physical key's register. [3](#0-2) 

4. `getAccountKeysAndAggregateWeights` checks `accountKey.Revoked` — which is `false` for key index 1 — and lets the transaction through. [4](#0-3) 

---

### Title
Revoking Key Index 0 Does Not Revoke Duplicate Key at Index 1 — Unauthorized Account Access After Intended Full Revocation - (`fvm/environment/account_public_key_util.go`, `fvm/environment/accounts.go`)

### Summary
When the same public key K is registered at index 0 and again at index 1 (detected as a duplicate, `storedKeyIndex=0`, `saveKey=false`), revoking key index 0 via `RevokeAccountPublicKey(addr, 0)` only sets `Revoked=true` in the `apk_0` register. The per-index revoked bit for key index 1 in `keyMetadataBytes` is never updated. A subsequent call to `GetRuntimeAccountPublicKey(addr, 1)` returns `Revoked=false` because it reads the revoked status from the per-index metadata, not from the physical key register. A transaction signed with K referencing key index 1 therefore passes the `accountKey.Revoked` check in `getAccountKeysAndAggregateWeights`, granting unauthorized account access after an intended full revocation.

### Finding Description

The deduplication system stores per-index revoked bits independently in `keyMetadataBytes` (the `weightAndRevokedStatusBytes` section). When key K is added at index 1 as a duplicate of index 0, `AppendDuplicateKeyMetadata` records `revoked=false` for key 1 and a mapping `keyIndex 1 → storedKeyIndex 0`. [5](#0-4) 

When `RevokeAccountPublicKey(addr, 0)` is called, the `keyIndex == 0` branch dispatches to `revokeAccountPublicKey0`, which exclusively modifies the `apk_0` register: [6](#0-5) 

`revokeAccountPublicKey0` reads `apk_0`, sets `decodedPublicKey.Revoked = true`, and writes it back — with no awareness of any duplicate key indices that share this physical key: [7](#0-6) 

When `GetRuntimeAccountPublicKey(addr, 1)` is subsequently called, `AccountPublicKeyMetadata(1)` calls `GetKeyMetadata(keyMetadataBytes, 1, true)`, which reads the per-index revoked bit for key 1 from `weightAndRevokedStatusBytes` — returning `revoked=false`: [8](#0-7) 

`getStoredPublicKey(a, address, 0)` then reads from `apk_0` (which now has `Revoked=true`) but returns only a `StoredPublicKey{PublicKey, SignAlgo, HashAlgo}` — the `Revoked` field is structurally absent and the revoked status is discarded: [9](#0-8) 

The final `RuntimeAccountPublicKey` is assembled with `Revoked: revoked` where `revoked` is the stale `false` from per-index metadata: [10](#0-9) 

### Impact Explanation
A transaction signed with K referencing key index 1 passes the revocation guard in `getAccountKeysAndAggregateWeights`: [4](#0-3) 

This enables full account authorization using a key the account operator believed was revoked, allowing arbitrary transactions to be submitted and executed on behalf of the account.

### Likelihood Explanation
The precondition — the same key material appearing at two indices — is reachable via the normal `AddAccountKey` Cadence built-in. An attacker who has had temporary access to an account (e.g., via a compromised key or a multi-party setup) can pre-register a duplicate key at a second index. When the legitimate owner revokes the key at index 0, the duplicate at index 1 remains active. The exploit requires no privileged node access, no brute force, and is locally reproducible on the Flow emulator.

### Recommendation
`revokeAccountPublicKey0` must, after setting `Revoked=true` in `apk_0`, scan `keyMetadataBytes` for any key indices whose `storedKeyIndex` resolves to 0 (i.e., duplicates of key 0) and call `SetRevokedStatus` for each such index. Symmetrically, `RevokeAccountPublicKey` for `keyIndex > 0` must check whether the target key's `storedKeyIndex` is shared with other indices and revoke all of them. Alternatively, revocation should be stored on the physical stored key rather than per logical index, so that revoking any alias automatically revokes all aliases.

### Proof of Concept
```
1. Create account with key K at index 0.
2. Call AddAccountKey(K) → detected as duplicate of index 0; key 1 added with storedKeyIndex=0, revoked=false in keyMetadataBytes.
3. Call RevokeAccountKey(addr, 0) → apk_0.Revoked=true; keyMetadataBytes for index 1 unchanged.
4. Submit transaction signed with K, KeyIndex=1.
5. getAccountKeysAndAggregateWeights calls GetRuntimeAccountPublicKey(addr, 1):
   - AccountPublicKeyMetadata(1) → revoked=false (from keyMetadataBytes), storedKeyIndex=0
   - getStoredPublicKey(addr, 0) → reads apk_0, returns StoredPublicKey (no Revoked field)
   - Returns RuntimeAccountPublicKey{Revoked: false}
6. accountKey.Revoked == false → check passes → transaction authorized.
```

### Citations

**File:** fvm/environment/account_public_key_util.go (L79-116)
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

**File:** fvm/environment/accounts.go (L371-373)
```go
	if keyIndex == 0 {
		return revokeAccountPublicKey0(a, address)
	}
```

**File:** fvm/transactionVerifier.go (L305-308)
```go
		if accountKey.Revoked {
			return signature.newError(
				fmt.Errorf("account key has been revoked"))
		}
```

**File:** fvm/environment/accounts_status.go (L314-343)
```go
	}

	// Handle non-duplicate key.
	storedKeyIndex, err = keyMetadata.AppendUniqueKeyMetadata(revoked, weight, digest)
	if err != nil {
		return nil, 0, false, err
	}

	return keyMetadata, storedKeyIndex, true, nil
}


```

**File:** fvm/environment/account-key-metadata/metadata.go (L49-53)
```go
	// Get weight and revoked status for given account key index
	revoked, weight, err = getWeightAndRevokedStatus(weightAndRevokedStatusBytes, keyIndex-1)
	if err != nil {
		return 0, false, 0, err
	}
```
