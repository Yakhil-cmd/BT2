### Title
`MsgTurnBridge` Has No Permission Check and Is a Complete No-Op — Permanent Bridge Circuit-Breaker Bypass - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` gRPC handler in `x/cronos/keeper/msg_server.go` is implemented as a literal no-op (`return nil, nil`). It performs no permission check and writes no state. Any unprivileged user can call it and receive a success response, bypassing the `CanTurnBridge` permission system entirely. Simultaneously, the bridge circuit-breaker is permanently non-functional: even the authorized admin cannot disable the bridge.

### Finding Description
The Cronos permission system defines a `CanTurnBridge` bit-permission (value `2`) in `x/cronos/keeper/permissions.go`. The design intent (ADR-009) is that only addresses holding this permission (or the `CronosAdmin`) may enable or disable the gravity bridge as an emergency circuit-breaker.

The `UpdateTokenMapping` handler correctly enforces this pattern:

```go
// x/cronos/keeper/msg_server.go:72-75
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
```

The `TurnBridge` handler, however, is:

```go
// x/cronos/keeper/msg_server.go:84-87
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
```

There is no permission check, no state write, and no error. The function unconditionally returns success. No ante-handler or middleware compensates for this — `BlockAddressesDecorator` only inspects `MsgStoreBlockList`, not `MsgTurnBridge`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
Two distinct High-severity impacts arise:

1. **Authorization bypass**: Any unprivileged user can submit a `MsgTurnBridge` transaction and receive a success response (code 0). The `CanTurnBridge` permission check is completely absent. This directly satisfies: *"High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

2. **Permanent bridge circuit-breaker failure**: Because the handler writes no state, the bridge can never be disabled through this message — not even by the authorized admin. If the gravity bridge is being actively exploited (e.g., unauthorized minting or draining of `gravity0x…` tokens), the admin's only on-chain emergency stop mechanism is silently broken. This satisfies: *"High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows… under normal network assumptions."* [1](#0-0) 

### Likelihood Explanation
The entry path is fully unprivileged: any account with enough gas can broadcast a `MsgTurnBridge` transaction. The proto definition exposes the message on the public gRPC `Msg` service with no special routing. The missing enforcement is unconditional — there is no code path that reaches a permission check. [5](#0-4) 

### Recommendation
Implement `TurnBridge` analogously to `UpdateTokenMapping`:

1. Add a `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard that returns `ErrUnauthorized` on failure.
2. Persist the bridge-enabled state to the KV store (e.g., a `KeyPrefixBridgeEnabled` key) and read it in the gravity bridge EVM hook / end-blocker to gate bridge operations.
3. Add a corresponding query to expose the current bridge state on-chain. [6](#0-5) [7](#0-6) 

### Proof of Concept

```
# Any unprivileged account can call TurnBridge and receive code=0
cronosd tx cronos turn-bridge false \
  --from community \
  --chain-id cronos_777-1 \
  --gas-prices 100000000000basetcro \
  -y

# Expected (per ADR-009 design): code != 0 (ErrUnauthorized)
# Actual: code = 0, bridge state unchanged, no error
```

The integration test in `integration_tests/test_gravity.py` asserts `rsp["code"] != 0` for the community sender, but with the current no-op implementation the transaction succeeds for every sender, falsifying that assertion and confirming the missing enforcement. [8](#0-7) [1](#0-0)

### Citations

**File:** x/cronos/keeper/msg_server.go (L68-82)
```go
// UpdateTokenMapping implements the grpc method
func (k msgServer) UpdateTokenMapping(goCtx context.Context, msg *types.MsgUpdateTokenMapping) (*types.MsgUpdateTokenMappingResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// check permission
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}

	// msg is already validated
	if err := k.RegisterOrUpdateTokenMapping(ctx, msg); err != nil {
		return nil, err
	}
	return &types.MsgUpdateTokenMappingResponse{}, nil
}
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

**File:** app/block_address.go (L74-81)
```go
		admin := bad.getParams(ctx).CronosAdmin
		for _, msg := range tx.GetMsgs() {
			if blocklistMsg, ok := msg.(*types.MsgStoreBlockList); ok {
				if admin != blocklistMsg.From {
					return ctx, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
				}
			}
		}
```

**File:** proto/cronos/tx.proto (L81-89)
```text
// MsgTurnBridge defines the request type
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}

// MsgTurnBridgeResponse defines the response type
message MsgTurnBridgeResponse {}
```

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```
