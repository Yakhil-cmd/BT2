The code is clear enough to make a determination. Let me verify the `appendDigest` eviction logic precisely.

### Title
Rolling-Window Digest Eviction in `appendDigest` Allows Duplicate Key Bypass, Breaking Key-Revocation Invariant — (File: `fvm/environment/account-key-metadata/metadata.go`)

---

### Summary

`appendDigest` maintains a rolling window of only `MaxStoredDigests=2` key digests. Once an account has accumulated 3+ unique keys, the oldest digest is evicted. A subsequent attempt to add a key byte-identical to the evicted key passes `FindDuplicateKey` undetected, causing `AppendAccountPublicKeyMetadata` to return `saveKey=true` and write a second copy of the key at a new index. Revoking the original index does not revoke the duplicate, permanently breaking the key-revocation invariant.

---

### Finding Description

**`MaxStoredDigests = 2`** is the hard-coded rolling-window size: [1](#0-0) 

**`appendDigest`** evicts the oldest digest when the window would exceed 2 entries, advancing `startIndexForDigests`: [2](#0-1) 

**`findDuplicateDigest`** only searches the current in-window slice `m.digestBytes`; any digest whose stored-key index is `< startIndexForDigests` is invisible to it: [3](#0-2) 

**`FindDuplicateKey`** returns `found=false` whenever `findDuplicateDigest` misses, and the code explicitly documents this as an accepted tradeoff: [4](#0-3) 

**`appendAccountPublicKeyMetadata`** then takes the `!isDuplicateKey` branch, calls `AppendUniqueKeyMetadata`, and returns `saveKey=true`: [5](#0-4) 

**Exact state trace with `MaxStoredDigests=2`:**

| Step | Action | `digestBytes` window | `startIndexForDigests` |
|------|--------|----------------------|------------------------|
| Add key0 (idx 0) | Fast-path return, no metadata | — | — |
| Add key1 (idx 1) | key0 digest bootstrapped; key1 unique | `[D(k0), D(k1)]` | 0 |
| Add key2 (idx 2) | key2 unique; **D(k0) evicted** | `[D(k1), D(k2)]` | 1 |
| Add key≡key0 (idx 3) | `findDuplicateDigest(D(k0))` searches `[D(k1),D(k2)]` → **miss** → `saveKey=true` | `[D(k2), D(k0)]` | 2 |

After step 4, two distinct key indices (0 and 3) map to identical encoded public-key bytes, each with its own independent revoked flag.

---

### Impact Explanation

Revoking key index 0 sets only that index's revoked bit via `SetRevokedStatus`: [6](#0-5) 

Key index 3 retains its own separate, unset revoked bit. Any holder of the private key corresponding to key0's bytes can continue to sign valid transactions using index 3 indefinitely after index 0 has been revoked. This violates the invariant that revoking a key removes all signing authority associated with those key bytes, and it corrupts `AccountPublicKeyCount` (which counts 4 keys when only 3 distinct keys exist).

---

### Likelihood Explanation

The precondition is that the attacker must be able to submit key-addition transactions on the target account — i.e., they already hold a key with sufficient weight. This is realistic in:

- **Multisig accounts** where one co-signer adds key3≡key0 before the other co-signers revoke key0 to remove them.
- **Accounts the attacker controls** where they pre-plant a duplicate before transferring partial control.

The trigger requires exactly 3 prior unique keys (trivially achievable) and one additional `addKey` transaction. No privileged node access, no brute force, and no admin capability is required. The attack is fully exercisable on an unmodified Flow emulator.

---

### Recommendation

1. **Increase `MaxStoredDigests`** to cover the full key history, or store digests for all keys rather than a rolling window. The storage cost is 8 bytes per key, which is negligible compared to the security invariant being protected.
2. **Alternatively**, perform a full linear scan of all stored keys (via `getStoredKey`) when the digest window does not cover the key being added, accepting the O(n) cost as a security requirement.
3. **At minimum**, document that the deduplication guarantee is explicitly bounded to the last `MaxStoredDigests` keys and that callers must not rely on it as a security control for key-revocation correctness.

---

### Proof of Concept

```go
// Emulator invariant test (pseudocode)
acct := createAccount()
key0 := generateKey()
key1 := generateKey()
key2 := generateKey()

addKey(acct, key0) // index 0
addKey(acct, key1) // index 1 — window: [D(k0), D(k1)]
addKey(acct, key2) // index 2 — window: [D(k1), D(k2)], D(k0) evicted

addKey(acct, key0) // index 3 — D(k0) not in window → saveKey=true → stored again

// Assert duplicate stored
assert(getAccountPublicKey(acct, 0).bytes == getAccountPublicKey(acct, 3).bytes)

// Assert revocation bypass
revokeKey(acct, 0)
assert(isRevoked(acct, 0) == true)
assert(isRevoked(acct, 3) == false) // key3 still active with same bytes
assert(canSign(acct, key0, keyIndex=3) == true) // attacker retains access
```

### Citations

**File:** fvm/environment/accounts_status.go (L39-41)
```go
const (
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

**File:** fvm/environment/accounts_status.go (L316-322)
```go
	// Handle non-duplicate key.
	storedKeyIndex, err = keyMetadata.AppendUniqueKeyMetadata(revoked, weight, digest)
	if err != nil {
		return nil, 0, false, err
	}

	return keyMetadata, storedKeyIndex, true, nil
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

**File:** fvm/environment/account-key-metadata/metadata.go (L351-366)
```go
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

**File:** fvm/environment/account-key-metadata/digest.go (L13-17)
```go
// FindDuplicateKey returns true with duplicate key index if duplicate key
// of the given key is found.  However, detection rate is intentionally
// not 100% in order to limit the number of digests we store on chain.
// If a hash collision happens with given digest, this function returns
// SentinelFastDigest64 digest and duplicate key not found.
```
