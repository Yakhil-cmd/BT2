### Title
Unbounded KV Index Scan in `BlockSearch` Enables Unauthenticated Resource-Exhaustion DoS — (`sei-tendermint/internal/rpc/core/blocks.go`)

---

### Summary

`BlockSearch` fetches **all** matching block heights from the KV indexer into memory and sorts them before applying the per-page cap. An unauthenticated attacker can send a broad query (e.g., `block.height > 0`) that matches every indexed block, forcing the node to allocate and sort a `[]int64` proportional to the entire chain history on every request. Concurrent requests multiply the effect and can exhaust memory or CPU, crashing the RPC node.

---

### Finding Description

**Root cause — pagination applied after full scan**

`BlockSearch` calls `kvsink.SearchBlockEvents(ctx, q)`, which delegates to `BlockerIndexer.Search`. That function has **no result-count limit**: it iterates the entire KV store for any non-exact-height query and returns every matching height. [1](#0-0) 

The full `[]int64` slice is then sorted in-place: [2](#0-1) 

Only **after** the sort does `validatePerPage` cap the output at `maxPerPage = 100`: [3](#0-2) 

So the per-page cap protects the response size but does nothing to bound the scan or the in-memory allocation.

**KV indexer — no limit in `Search`**

`BlockerIndexer.Search` iterates the entire prefix for range, equality, `EXISTS`, `CONTAINS`, and `MATCHES` operators with no cap on `filteredHeights`: [4](#0-3) [5](#0-4) [6](#0-5) 

**KV indexer enabled by default**

The default tx-index configuration enables the KV sink, so `BlockSearch` is reachable on any default node: [7](#0-6) 

**RPC endpoint publicly accessible on RPC nodes**

The docker RPC-node config binds to `0.0.0.0:26657` with no authentication: [8](#0-7) 

---

### Impact Explanation

For a chain with N indexed blocks, a query `block.height > 0` causes:

1. A full KV prefix scan returning N `int64` heights (~8 bytes each; 10 M blocks ≈ 80 MB per request).
2. An O(N log N) in-memory sort of the full slice.
3. Only then is the 100-item page extracted.

With `MaxOpenConnections = 900`, an attacker can issue hundreds of concurrent broad queries. Each goroutine holds its own allocation for up to the 30-second write timeout. The combined allocation easily exceeds available RAM, causing an OOM kill or sustained CPU saturation that makes the node unresponsive. [9](#0-8) 

---

### Likelihood Explanation

- No authentication is required; the `/block_search` endpoint is documented and publicly reachable.
- The query syntax is documented in the OpenAPI spec. [10](#0-9) 

- A single HTTP GET with `query=block.height>0` is sufficient to trigger the full scan.
- The attack is trivially scriptable and requires no funds.

---

### Recommendation

1. **Cap results inside `BlockerIndexer.Search`**: accept a `limit int` parameter and stop accumulating heights once the limit is reached, returning early.
2. **Pass the limit from `BlockSearch`**: use `maxPerPage * maxReasonablePages` (e.g., 10 000) as the hard cap passed into `SearchBlockEvents`.
3. **Reject or bound wildcard queries**: reject queries with no lower-bound height constraint, or require `block.height >= X` to scope the scan.
4. **Add a per-IP or global rate limit** on search endpoints.

---

### Proof of Concept

```bash
# On a node with many indexed blocks, run concurrently:
for i in $(seq 1 200); do
  curl -s "http://<rpc-node>:26657/block_search?query=block.height%3E0&per_page=1&page=1" &
done
wait
```

Each request forces a full KV scan + sort of all indexed heights. With 200 concurrent requests on a chain with millions of blocks, RSS grows proportionally to `200 × N × 8 bytes`. On a chain with 10 M blocks this is ~16 GB of live allocations, triggering OOM or sustained 100 % CPU from the concurrent sorts.

The `ctx.Done()` check inside the iterator loop provides cancellation only after the 30-second write timeout fires; it does not prevent the allocation from occurring. [11](#0-10) [12](#0-11)

### Citations

**File:** sei-tendermint/internal/rpc/core/blocks.go (L322-325)
```go
	results, err := kvsink.SearchBlockEvents(ctx, q)
	if err != nil {
		return nil, err
	}
```

**File:** sei-tendermint/internal/rpc/core/blocks.go (L328-337)
```go
	switch req.OrderBy {
	case "desc", "":
		sort.Slice(results, func(i, j int) bool { return results[i] > results[j] })

	case "asc":
		sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })

	default:
		return nil, fmt.Errorf("expected order_by to be either `asc` or `desc` or empty: %w", coretypes.ErrInvalidRequest)
	}
```

**File:** sei-tendermint/internal/rpc/core/env.go (L139-153)
```go
func (env *Environment) validatePerPage(perPagePtr *int) int {
	if perPagePtr == nil { // no per_page parameter
		return defaultPerPage
	}

	perPage := *perPagePtr
	if perPage < 1 {
		return defaultPerPage
		// in unsafe mode there is no max on the page size but in safe mode
		// we cap it to maxPerPage
	} else if perPage > maxPerPage && !env.Config.Unsafe {
		return maxPerPage
	}
	return perPage
}
```

**File:** sei-tendermint/internal/state/indexer/block/kv/kv.go (L81-106)
```go
func (idx *BlockerIndexer) Search(ctx context.Context, q *query.Query) ([]int64, error) {
	results := make([]int64, 0)
	select {
	case <-ctx.Done():
		return results, nil

	default:
	}

	conditions := q.Syntax()

	// If there is an exact height query, return the result immediately
	// (if it exists).
	height, ok := lookForHeight(conditions)
	if ok {
		ok, err := idx.Has(height)
		if err != nil {
			return nil, err
		}

		if ok {
			return []int64{height}, nil
		}

		return results, nil
	}
```

**File:** sei-tendermint/internal/state/indexer/block/kv/kv.go (L194-200)
```go
		select {
		case <-ctx.Done():
			break heights

		default:
		}
	}
```

**File:** sei-tendermint/internal/state/indexer/block/kv/kv.go (L213-280)
```go
func (idx *BlockerIndexer) matchRange(
	ctx context.Context,
	qr indexer.QueryRange,
	startKey []byte,
	filteredHeights map[string][]byte,
	firstRun bool,
) (map[string][]byte, error) {

	// A previous match was attempted but resulted in no matches, so we return
	// no matches (assuming AND operand).
	if !firstRun && len(filteredHeights) == 0 {
		return filteredHeights, nil
	}

	tmpHeights := make(map[string][]byte)
	lowerBound := qr.LowerBoundValue()
	upperBound := qr.UpperBoundValue()

	it, err := dbm.IteratePrefix(idx.store, startKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create prefix iterator: %w", err)
	}
	defer func() { _ = it.Close() }()

iter:
	for ; it.Valid(); it.Next() {
		var (
			eventValue string
			err        error
		)

		if qr.Key == types.BlockHeightKey {
			eventValue, err = parseValueFromPrimaryKey(it.Key())
		} else {
			eventValue, err = parseValueFromEventKey(it.Key())
		}

		if err != nil {
			continue
		}

		if _, ok := qr.AnyBound().(int64); ok {
			v, err := strconv.ParseInt(eventValue, 10, 64)
			if err != nil {
				continue iter
			}

			include := true
			if lowerBound != nil && v < lowerBound.(int64) {
				include = false
			}

			if upperBound != nil && v > upperBound.(int64) {
				include = false
			}

			if include {
				tmpHeights[string(it.Value())] = it.Value()
			}
		}

		select {
		case <-ctx.Done():
			break iter

		default:
		}
	}
```

**File:** sei-tendermint/internal/state/indexer/block/kv/kv.go (L338-355)
```go
	case syntax.TEq:
		it, err := dbm.IteratePrefix(idx.store, startKeyBz)
		if err != nil {
			return nil, fmt.Errorf("failed to create prefix iterator: %w", err)
		}
		defer func() { _ = it.Close() }()

		for ; it.Valid(); it.Next() {
			tmpHeights[string(it.Value())] = it.Value()

			if err := ctx.Err(); err != nil {
				break
			}
		}

		if err := it.Error(); err != nil {
			return nil, err
		}
```

**File:** sei-tendermint/config/config.go (L524-552)
```go
func DefaultRPCConfig() *RPCConfig {
	return &RPCConfig{
		ListenAddress:      "tcp://127.0.0.1:26657",
		CORSAllowedOrigins: []string{},
		CORSAllowedMethods: []string{http.MethodHead, http.MethodGet, http.MethodPost},
		CORSAllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "X-Server-Time"},

		Unsafe:             false,
		MaxOpenConnections: 900,

		// Settings for event subscription.
		MaxSubscriptionClients:       100,
		MaxSubscriptionsPerClient:    5,
		ExperimentalDisableWebsocket: false, // compatible with TM v0.35 and earlier
		EventLogWindowSize:           30 * time.Second,
		EventLogMaxItems:             0,

		TimeoutBroadcastTxCommit: 10 * time.Second,

		MaxBodyBytes:   int64(1000000), // 1MB
		MaxHeaderBytes: 1 << 20,        // same as the net/http default

		TLSCertFile:  "",
		TLSKeyFile:   "",
		LagThreshold: 300,

		TimeoutRead:  10 * time.Second,
		TimeoutWrite: 30 * time.Second,
	}
```

**File:** sei-tendermint/config/config.go (L1354-1357)
```go
// DefaultTxIndexConfig returns a default configuration for the transaction indexer.
func DefaultTxIndexConfig() *TxIndexConfig {
	return &TxIndexConfig{Indexer: []string{"kv"}}
}
```

**File:** docker/rpcnode/config/config.toml (L94-96)
```text
# TCP or UNIX socket address for the RPC server to listen on
laddr = "tcp://0.0.0.0:26657"

```

**File:** sei-tendermint/rpc/openapi/openapi.yaml (L1314-1368)
```yaml
  /block_search:
    get:
      summary: Search for blocks by BeginBlock and EndBlock events
      description: |
        Search for blocks by BeginBlock and EndBlock events.

        See /subscribe for the query syntax.
      operationId: block_search
      parameters:
        - in: query
          name: query
          description: Query
          required: true
          schema:
            type: string
            example: "block.height > 1000 AND valset.changed > 0"
        - in: query
          name: page
          description: "Page number (1-based)"
          required: false
          schema:
            type: integer
            default: 1
            example: 1
        - in: query
          name: per_page
          description: "Number of entries per page (max: 100)"
          required: false
          schema:
            type: integer
            default: 30
            example: 30
        - in: query
          name: order_by
          description: Order in which blocks are sorted ("asc" or "desc"), by height. If empty, default sorting will be still applied.
          required: false
          schema:
            type: string
            default: "desc"
            example: "asc"
      tags:
        - Info
      responses:
        "200":
          description: List of paginated blocks matching the search criteria.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BlockResultsResponse"
        "500":
          description: Error
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"
```
