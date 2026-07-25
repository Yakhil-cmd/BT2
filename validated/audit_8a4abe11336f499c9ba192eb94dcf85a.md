Based on my analysis of `storage/statedb/sync.go` and the grep results from `node/cn/snap/sync.go`, this is a real vulnerability.

---

### Title
Missing keccak256 Integrity Check for Code Entries in `TrieSync.Process` Allows Malicious Sync Peer to Corrupt Contract Bytecode — (`storage/statedb/sync.go`)

### Summary

`TrieSync.Process` stores contract bytecode supplied by a sync peer directly into `membatch.codes[req.hash]` without verifying that `keccak256(result.Data) == result.Hash`. A malicious snap-heal peer can supply arbitrary bytecode for any legitimately requested code hash, causing the syncing node to persistently store and execute attacker-controlled bytecode under the identity of victim contracts.

### Finding Description

In `TrieSync.Process`, the code-request branch (lines 311–314) assigns `req.data = result.Data` and immediately calls `s.commit(req)` with no hash integrity check: [1](#0-0) 

By contrast, the node-request branch calls `decodeNode(result.Hash[:], result.Data)` which implicitly verifies the hash: [2](#0-1) 

`commit` then writes the unverified data directly into `membatch.codes` keyed by the requested hash: [3](#0-2) 

`Commit` then persists this to the database under `database.CodeKey(key)`: [4](#0-3) 

A grep for `crypto.Keccak256` in `node/cn/snap/sync.go` returns **no matches**, confirming that neither `processTrienodeHealResponse` nor `processCodeHealResponse` performs the verification before calling `TrieSync.Process`. [5](#0-4) 

### Impact Explanation

After sync completes, any contract account whose `codeHash` was targeted will have attacker-supplied bytecode stored under that hash. When the EVM loads contract code via `codeHash` lookup, it retrieves and executes the malicious bytecode. This enables:
- Arbitrary balance drain from any contract whose code was synced
- State corruption (storage writes, self-destruct, delegatecall pivots)
- Persistent, durable corruption of the code hash → bytecode mapping

This satisfies: *"Persistent corruption of trie/state/snapshot data that breaks canonical execution"* and *"Invalid state transition … on honest nodes."*

### Likelihood Explanation

The attacker only needs to be a reachable P2P peer during snap-heal sync (a permissionless role). Snap-heal is triggered automatically when a node syncs from a pivot block. The attacker observes which code hashes are requested (they are sent in the heal request) and responds with a crafted `SyncResult` containing malicious bytecode for any of those hashes.

### Recommendation

Add a hash integrity check in the code-request branch of `TrieSync.Process` before assigning `req.data`:

```go
if req := s.codeReqs[result.Hash]; req != nil && req.data == nil {
    // Verify integrity: keccak256(data) must equal the requested hash
    if crypto.Keccak256Hash(result.Data) != result.Hash {
        return fmt.Errorf("code hash mismatch: got %x, want %x",
            crypto.Keccak256Hash(result.Data), result.Hash)
    }
    filled = true
    req.data = result.Data
    s.commit(req)
}
```

### Proof of Concept

1. Create a `TrieSync` with a `codeReqs` entry for `legitimateCodeHash`.
2. Call `ts.Process(SyncResult{Hash: legitimateCodeHash, Data: maliciousCode})` where `keccak256(maliciousCode) != legitimateCodeHash`.
3. Assert `ts.membatch.codes[legitimateCodeHash] == maliciousCode` — this passes with no error.
4. Call `ts.Commit(batch)` and read back `database.CodeKey(legitimateCodeHash)` — it returns `maliciousCode`.
5. Confirm `keccak256(maliciousCode) != legitimateCodeHash`, proving the invariant is violated. [6](#0-5)

### Citations

**File:** storage/statedb/sync.go (L304-344)
```go
func (s *TrieSync) Process(result SyncResult) error {
	// If the item was not requested either for code or node, bail out
	if s.nodeReqs[result.Hash] == nil && s.codeReqs[result.Hash] == nil {
		return ErrNotRequested
	}
	// There is an pending code request for this data, commit directly
	var filled bool
	if req := s.codeReqs[result.Hash]; req != nil && req.data == nil {
		filled = true
		req.data = result.Data
		s.commit(req)
	}
	// There is an pending node request for this data, fill it.
	if req := s.nodeReqs[result.Hash]; req != nil && req.data == nil {
		filled = true
		// Decode the node data content and update the request
		node, err := decodeNode(result.Hash[:], result.Data)
		if err != nil {
			return err
		}
		req.data = result.Data

		// Create and schedule a request for all the children nodes
		requests, err := s.children(req, node)
		if err != nil {
			return err
		}
		if len(requests) == 0 && req.deps == 0 {
			s.commit(req)
		} else {
			req.deps += len(requests)
			for _, child := range requests {
				s.schedule(child)
			}
		}
	}
	if !filled {
		return ErrAlreadyProcessed
	}
	return nil
}
```

**File:** storage/statedb/sync.go (L363-365)
```go
	for key, value := range s.membatch.codes {
		if err := dbw.Put(database.CodeKey(key), value); err != nil {
			return written, err
```

**File:** storage/statedb/sync.go (L514-516)
```go
	if req.code {
		s.membatch.codes[req.hash] = req.data
		delete(s.codeReqs, req.hash)
```

**File:** node/cn/snap/sync.go (L1-1)
```go
// Modifications Copyright 2024 The Kaia Authors
```
