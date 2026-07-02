### Title
Contract Deployment Index Namespace Collision via Missing Delimiter in Key Construction - (File: `storage/indexes/contracts.go`)

### Summary

The `ContractDeploymentsIndex` constructs storage keys by concatenating a variable-length contract name directly against a fixed-length `~height` field with no delimiter. Because the contract name is unbounded and immediately precedes the one's-complement height bytes (which begin with `0xFF` for all practical heights), the byte-prefix for contract `"Token"` is also a byte-prefix of every key for contract `"TokenV2"`. This causes `ByContract` and `DeploymentsByContract` to scan and return entries belonging to the wrong contract.

### Finding Description

The primary key format is:

```
[codeContractDeployment(1)] [address(8)] [contract name (variable)] [~height(8)] [txIndex(4)] [eventIndex(4)]
```

`makeContractDeploymentContractPrefix` builds the lookup prefix as:

```
[codeContractDeployment] [address(8)] [contract name bytes]
```

with no terminating delimiter after the name. [1](#0-0) 

Because the one's-complement of any realistic block height starts with `0xFF` (e.g., `~100 = 0xFFFFFFFFFFFFFF9B`), the first byte after the name in a real key is always `0xFF`. The ASCII character `V` in `"TokenV2"` is `0x56 < 0xFF`, so the full key for `"TokenV2"` at any height sorts **before** the full key for `"Token"` at any height in lexicographic order.

Concretely, for address `A`:

| Contract | Height | Key bytes after address |
|---|---|---|
| `TokenV2` | 50 | `TokenV2\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xCD...` |
| `Token` | 100 | `Token\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x9B...` |

The prefix `[code][A][Token]` matches both rows because `"TokenV2"` starts with `"Token"`. Since `"TokenV2"` entries sort first, `ByContract(A, "Token")` returns the iterator's first item — the most recent `"TokenV2"` deployment — not `"Token"`. [2](#0-1) 

`DeploymentsByContract(A, "Token", nil)` returns the full history of both `"Token"` and `"TokenV2"` (and any other contract whose name starts with `"Token"`). [3](#0-2) 

The range keys for the cursor-nil case pass `prefix, prefix` to `NewIter`, which the storage layer treats as a prefix scan: [4](#0-3) 

The only input validation rejects empty names and names containing `"."`, but does **not** prevent one name from being a byte-prefix of another: [5](#0-4) 

### Impact Explanation

An Access node's contract deployment index returns incorrect data. `ByContract(addr, "Token")` silently returns the deployment record (including code and code hash) of `"TokenV2"` instead of `"Token"`. `DeploymentsByContract(addr, "Token")` returns a merged history of all contracts whose names share the `"Token"` prefix. Consumers of the Access API — wallets, block explorers, auditing tools — receive wrong contract code and metadata, potentially leading to incorrect security assessments or user decisions about which contract version is live.

### Likelihood Explanation

Any Flow account that deploys two contracts where one name is a byte-prefix of another (e.g., `"Token"` / `"TokenV2"`, `"Vault"` / `"VaultV2"`, `"NFT"` / `"NFTMinter"`) triggers the collision. This is a common naming pattern in production contract ecosystems. No special privileges are required; any unprivileged transaction sender can deploy such contracts to their own account, and the corruption of the index query results is then observable by all Access API callers.

### Recommendation

Add a fixed-length delimiter (e.g., a null byte `0x00` or a length-prefix) between the contract name and the `~height` field in both `makeContractDeploymentKey` and `makeContractDeploymentContractPrefix`. For example:

```
[codeContractDeployment][address(8)][contract name][0x00][~height(8)][txIndex(4)][eventIndex(4)]
```

This ensures no contract name is a byte-prefix of another contract's key segment, eliminating the namespace collision. [6](#0-5) 

### Proof of Concept

1. Account `A` deploys contract `"Token"` at height 100 and contract `"TokenV2"` at height 50.
2. Both are stored in the index:
   - Key for `"Token"`: `[code][A]Token\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x9B\x00\x00\x00\x00\x00\x00\x00\x00`
   - Key for `"TokenV2"`: `[code][A]TokenV2\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xCD\x00\x00\x00\x00\x00\x00\x00\x00`
3. `makeContractDeploymentContractPrefix(A, "Token")` returns `[code][A]Token`.
4. This prefix matches both keys. In lexicographic order, `"TokenV2"` key sorts before `"Token"` key (since `'V'=0x56 < 0xFF`).
5. `ByContract(A, "Token")` calls `DeploymentsByContract`, which iterates from the prefix. The first item is the `"TokenV2"` entry.
6. `ByContract` returns the `"TokenV2"` deployment record, claiming it is the deployment of `"Token"`. [7](#0-6)

### Citations

**File:** storage/indexes/contracts.go (L113-134)
```go
// ByContract returns the most recent deployment for the given contract.
//
// Expected error returns during normal operation:
//   - [storage.ErrNotFound]: if no deployment for the given contract exists
func (idx *ContractDeploymentsIndex) ByContract(account flow.Address, name string) (access.ContractDeployment, error) {
	// pass a nil cursor to indicate search should start from the latest deployment
	iter, err := idx.DeploymentsByContract(account, name, nil)
	if err != nil {
		return access.ContractDeployment{}, fmt.Errorf("could not get deployments for %s.%s: %w", account.Hex(), name, err)
	}

	// iterate over deployments for the contract, and return the first one (most recent)
	for item, err := range iter {
		if err != nil {
			return access.ContractDeployment{}, fmt.Errorf("could not iterate contract deployments for %s.%s: %w", account.Hex(), name, err)
		}
		return item.Value()
	}

	// no deployments were found
	return access.ContractDeployment{}, storage.ErrNotFound
}
```

**File:** storage/indexes/contracts.go (L146-163)
```go
func (idx *ContractDeploymentsIndex) DeploymentsByContract(
	account flow.Address,
	name string,
	cursor *access.ContractDeploymentsCursor,
) (storage.ContractDeploymentIterator, error) {
	startKey, endKey, err := idx.rangeKeysByContract(account, name, cursor)
	if err != nil {
		return nil, fmt.Errorf("could not determine range keys: %w", err)
	}

	reader := idx.db.Reader()
	storageIter, err := reader.NewIter(startKey, endKey, storage.DefaultIteratorOptions())
	if err != nil {
		return nil, fmt.Errorf("could not create iterator for contract %s.%s: %w", account.Hex(), name, err)
	}

	return iterator.Build(storageIter, decodeDeploymentCursor, reconstructContractDeployment), nil
}
```

**File:** storage/indexes/contracts.go (L236-253)
```go
func (idx *ContractDeploymentsIndex) rangeKeysByContract(account flow.Address, name string, cursor *access.ContractDeploymentsCursor) (startKey, endKey []byte, err error) {
	prefix := makeContractDeploymentContractPrefix(account, name)

	latestHeight := idx.latestHeight.Load()
	if cursor == nil {
		// by default, iterate over all deployments for the contract
		return prefix, prefix, nil
	}

	if err := validateCursorHeight(cursor.BlockHeight, idx.firstHeight, latestHeight); err != nil {
		return nil, nil, err
	}

	startKey = makeContractDeploymentKey(account, name, cursor.BlockHeight, cursor.TransactionIndex, cursor.EventIndex)
	endKey = storage.PrefixInclusiveEnd(prefix, startKey)

	return startKey, endKey, nil
}
```

**File:** storage/indexes/contracts.go (L318-321)
```go
	for _, d := range deployments {
		if d.ContractName == "" || strings.Contains(d.ContractName, ".") {
			return fmt.Errorf("deployment for %s has invalid contract name: %q", d.Address.Hex(), d.ContractName)
		}
```

**File:** storage/indexes/contracts.go (L345-372)
```go
// makeContractDeploymentKey creates a primary key for the given address, contract name, height,
// txIndex, and eventIndex.
//
// Key format: [codeContractDeployment][address bytes(8)][contract name][~height(8)][txIndex(4)][eventIndex(4)]
func makeContractDeploymentKey(addr flow.Address, name string, height uint64, txIndex, eventIndex uint32) []byte {
	nameBytes := []byte(name)
	key := make([]byte, contractDeploymentKeyOverhead+len(nameBytes))
	offset := 0

	key[offset] = codeContractDeployment
	offset++

	copy(key[offset:], addr[:])
	offset += flow.AddressLength

	copy(key[offset:], nameBytes)
	offset += len(nameBytes)

	binary.BigEndian.PutUint64(key[offset:], ^height) // one's complement for descending height order
	offset += heightLen

	binary.BigEndian.PutUint32(key[offset:], txIndex)
	offset += txIndexLen

	binary.BigEndian.PutUint32(key[offset:], eventIndex)

	return key
}
```

**File:** storage/indexes/contracts.go (L374-385)
```go
// makeContractDeploymentContractPrefix returns the prefix used to iterate over all deployments
// of a specific contract:
//
//	[codeContractDeployment][address bytes(8)][contract name bytes]
func makeContractDeploymentContractPrefix(addr flow.Address, name string) []byte {
	nameBytes := []byte(name)
	prefix := make([]byte, 1+flow.AddressLength+len(nameBytes))
	prefix[0] = codeContractDeployment
	copy(prefix[1:], addr[:])
	copy(prefix[1+flow.AddressLength:], nameBytes)
	return prefix
}
```

**File:** storage/indexes/contracts.go (L408-416)
```go
func contractDeploymentKeyPrefix(key []byte) ([]byte, error) {
	if len(key) < minValidKeyLen {
		return nil, fmt.Errorf("key too short: expected at least %d bytes, got %d", minValidKeyLen, len(key))
	}
	if key[0] != codeContractDeployment {
		return nil, fmt.Errorf("invalid key prefix: expected %d, got %d", codeContractDeployment, key[0])
	}
	return key[:len(key)-heightLen-txIndexLen-eventIndexLen], nil
}
```
