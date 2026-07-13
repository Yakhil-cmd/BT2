### Title
Unauthenticated Panic-Induced DoS on IBC `ClientStates` gRPC/REST Handler via Stale Consensus-State Subkeys — (`app/upgrades.go`)

---

### Summary
Stale 3-segment IBC consensus-state store keys left behind by the pre-v9 ibc-go migration are never cleaned up before the v1.8 upgrade executes. The `ClientStates` gRPC handler iterates over all `clients/` prefixed keys and attempts to proto-unmarshal each value as a `ClientState` object. When it encounters a stale key of the form `clients/<id>/consensusStates/<rev>/<h>/clientState`, the unmarshal panics. Any unauthenticated caller can trigger this panic by issuing a single HTTP GET to `/ibc/core/client/v1/client_states`, permanently disabling the endpoint until the upgrade runs and the stale keys are pruned.

---

### Finding Description
The ibc-go v7 migration only cleaned canonical 2-segment `consensusStates` keys. 3-segment variants of the form:

```
clients/<id>/consensusStates/<revision>/<height>/clientState
```

survived in the KV store. The `ClientStates` gRPC handler uses a prefix iterator over `host.KeyClientStorePrefix` (`clients/`) and attempts to decode every value it finds as a `ClientState` proto message. A stale 3-segment key stores a `ConsensusState` blob (or garbage) at a path the handler treats as a `ClientState` slot — the unmarshal panics.

The Cronos upgrade handler (`app/upgrades.go`) explicitly documents this root cause and fixes it by calling `pruneStaleIBCConsensusStateSubkeys` at upgrade height:

```go
// 3-segment variants (clients/<id>/consensusStates/<rev>/<h>/clientState)
// survived and cause the ClientStates gRPC handler to panic on unmarshal,
// enabling an unauthenticated REST DoS via GET /ibc/core/client/v1/client_states.
```

The pruning function (`pruneStaleIBCConsensusStateSubkeys`) identifies and deletes keys where `len(parts) >= 5 && parts[2] == "consensusStates" && parts[len(parts)-1] == "clientState"`. Before the upgrade executes, every call to the `ClientStates` endpoint hits the panic path.

The integration test `integration_tests/ibc_v18.py` confirms the endpoint is panic-free only **after** the upgrade, and explicitly states the pre-upgrade state causes "an unauthenticated REST DoS."

---

### Impact Explanation
**High — Permanent long-lived inability for honest users and IBC relayers to use the `ClientStates` endpoint, disrupting IBC transfer flows.**

IBC relayers (e.g., Hermes, Go-relayer) query `ClientStates` to enumerate live clients and decide whether `MsgUpdateClient` submissions are needed. With the endpoint permanently panicking:

1. Relayers cannot enumerate IBC clients.
2. Relayers cannot determine which clients are approaching expiry.
3. Expired IBC light clients freeze their associated channels.
4. Frozen channels block all IBC token transfers (inbound and outbound) on those channels until governance unfreezes them — a process requiring a governance proposal and vote.

This maps directly to the allowed High impact: *"Permanent or long-lived inability for honest users or validators to process … IBC transfers … under normal network assumptions."*

---

### Likelihood Explanation
- **No authentication required.** A single unauthenticated HTTP GET to `/ibc/core/client/v1/client_states` triggers the panic.
- **No special state setup required.** The stale keys are already present in the store from the pre-v9 ibc-go migration; the attacker contributes nothing.
- **Repeatable.** Every call to the endpoint re-triggers the panic until the upgrade runs.
- **Publicly documented endpoint.** The IBC REST API is standard and well-known to any IBC ecosystem participant.

---

### Recommendation
Execute the v1.8 upgrade, which calls `pruneStaleIBCConsensusStateSubkeys` to delete all stale 3-segment `consensusStates` subkeys before the `ClientStates` handler can encounter them. As a belt-and-suspenders measure, add a defensive length/type check in the `ClientStates` handler itself so that unexpected key shapes return an error rather than panic.

---

### Proof of Concept

**Pre-condition:** A Cronos node whose IBC store contains at least one stale key of the form `clients/<id>/consensusStates/<rev>/<h>/clientState` (present on any chain that ran ibc-go < v9 and has not yet applied the v1.8 upgrade).

**Steps:**

```bash
# 1. Identify a Cronos node running pre-v1.8 code
NODE="https://stagingapp.truffles.one"   # or any pre-upgrade Cronos RPC

# 2. Issue an unauthenticated GET to the ClientStates REST endpoint
curl -s "$NODE/ibc/core/client/v1/client_states"
# Expected result: panic-induced 500 / gRPC Internal error
# "failed to unmarshal client state" or similar proto decode panic

# 3. Confirm the endpoint is permanently broken (every subsequent call panics)
for i in $(seq 1 5); do
  curl -s -o /dev/null -w "%{http_code}\n" "$NODE/ibc/core/client/v1/client_states"
done
# All return 500; no recovery without the upgrade
```

**Root cause in code:** [1](#0-0) 

**Pruning logic (the fix):** [2](#0-1) 

**Integration test confirming pre-upgrade panic:** [3](#0-2)

### Citations

**File:** app/upgrades.go (L55-65)
```go
			// Prune stale IBC client store keys left by the pre-v9 ibc-go migration.
			// The v7 ibc-go migration only cleaned canonical 2-segment consensusStates
			// keys; 3-segment variants (clients/<id>/consensusStates/<rev>/<h>/clientState)
			// survived and cause the ClientStates gRPC handler to panic on unmarshal,
			// enabling an unauthenticated REST DoS via GET /ibc/core/client/v1/client_states.
			sdkCtx := sdk.UnwrapSDKContext(ctx)
			if err := pruneStaleIBCConsensusStateSubkeys(sdkCtx, runtime.KVStoreAdapter(
				runtime.NewKVStoreService(app.keys[ibcexported.StoreKey]).OpenKVStore(sdkCtx),
			)); err != nil {
				return toVM, fmt.Errorf("prune stale ibc consensus state subkeys: %w", err)
			}
```

**File:** app/upgrades.go (L84-104)
```go
func pruneStaleIBCConsensusStateSubkeys(ctx sdk.Context, store storetypes.KVStore) error {
	iterator := storetypes.KVStorePrefixIterator(store, host.KeyClientStorePrefix)
	defer sdk.LogDeferred(ctx.Logger(), func() error { return iterator.Close() })

	var staleKeys [][]byte
	for ; iterator.Valid(); iterator.Next() {
		// iterator.Key() includes the full "clients/" prefix.
		// Canonical: clients/<id>/clientState (3 parts)
		// Stale:     clients/<id>/consensusStates/<rev>/<h>/clientState (≥5 parts)
		parts := strings.Split(string(iterator.Key()), "/")
		if len(parts) >= 5 &&
			parts[2] == host.KeyConsensusStatePrefix &&
			parts[len(parts)-1] == host.KeyClientState {
			staleKeys = append(staleKeys, bytes.Clone(iterator.Key()))
		}
	}

	for _, k := range staleKeys {
		store.Delete(k)
	}
	return nil
```

**File:** integration_tests/ibc_v18.py (L1-7)
```python
"""
IBC test utilities for v1.8 upgrade testing.

Verifies that the ClientStates REST endpoint is panic-free after the v1.8
upgrade, which prunes stale consensusStates subkeys that could previously
cause an unauthenticated REST DoS.
"""
```
