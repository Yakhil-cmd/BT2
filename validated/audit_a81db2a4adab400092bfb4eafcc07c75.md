The `TurnBridge` handler is confirmed to be a complete stub. Here is the full analysis:

---

### Title
Bridge Disable Mechanism Permanently Non-Functional — (`x/cronos/keeper/msg_server.go`)

### Summary
`msgServer.TurnBridge` unconditionally returns `(nil, nil)` without performing any permission check, reading `msg.Enable`, or writing any state. The `CanTurnBridge` permission constant exists and is tested in isolation, but `HasPermission(..., CanTurnBridge)` is never called in any production code path. No bridge-enabled enforcement flag exists anywhere in the codebase. The bridge can never be disabled through the intended governance/admin path.

### Finding Description

`msgServer.TurnBridge` is a stub:

```go
// x/cronos/keeper/msg_server.go:85-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare with `UpdateTokenMapping`, which correctly gates on `HasPermission`:

```go
// x/cronos/keeper/msg_server.go:73-74
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

`CanTurnBridge` is defined as a distinct permission bit:

```go
// x/cronos/keeper/permissions.go:14-16
CanChangeTokenMapping uint64 = 1 << iota // 1
CanTurnBridge                             // 2
All = CanChangeTokenMapping | CanTurnBridge // 3
``` [3](#0-2) 

The proto schema confirms `MsgTurnBridge` carries a meaningful `enable` field and is intended to "disable or enable the gravity bridge": [4](#0-3) [5](#0-4) 

A search for any bridge-enabled enforcement (`BridgeEnabled`, `IsBridgeEnabled`, `bridge_enabled`) returns **zero matches** in production code. The handler writes no state key, so there is nothing downstream to enforce.

### Impact Explanation

Any authorized admin or governance actor calling `TurnBridge(enable=false)` receives a success response (`nil` error) but the bridge state is never mutated. Because no enforcement point checks a bridge-enabled flag, the bridge remains permanently open. In an emergency (e.g., an active exploit draining bridge funds), the intended emergency-stop mechanism is silently inoperative. This is a bypass of the Cronos admin/governance bridge-control authority.

### Likelihood Explanation

The broken handler is reachable by any sender who can submit a valid `MsgTurnBridge` transaction. No special preconditions are required to trigger the no-op. The failure is deterministic and unconditional.

### Recommendation

Implement `TurnBridge` analogously to `UpdateTokenMapping`:
1. Check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Read `msg.Enable` and write a bridge-enabled flag to the KV store (e.g., under a `KeyPrefixBridgeEnabled` key).
3. Add enforcement in `ConvertVouchersToEvmCoins` and `IbcTransferCoins` (or their callers) to reject operations when the bridge-enabled flag is `false`.

### Proof of Concept

```go
// Unit test sketch
func TestTurnBridgeIsNoop(t *testing.T) {
    // 1. Call TurnBridge(enable=false) with an authorized sender
    resp, err := msgSrv.TurnBridge(ctx, &types.MsgTurnBridge{Sender: admin, Enable: false})
    require.NoError(t, err)   // returns nil, nil — succeeds silently
    require.NotNil(t, resp)

    // 2. Assert no state key was written
    store := ctx.KVStore(storeKey)
    require.Nil(t, store.Get(types.KeyPrefixBridgeEnabled)) // no flag exists

    // 3. Bridge operations still succeed — bridge was never disabled
    err = keeper.ConvertVouchersToEvmCoins(ctx, userAddr, coins)
    require.NoError(t, err) // bridge is still open
}
```

### Citations

**File:** x/cronos/keeper/msg_server.go (L73-74)
```go
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
```

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
```

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** proto/cronos/tx.proto (L82-86)
```text
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}
```
