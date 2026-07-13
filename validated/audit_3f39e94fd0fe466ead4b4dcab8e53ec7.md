### Title
`MsgTurnBridge` Handler Is a No-Op: Bridge Circuit Breaker Permanently Non-Functional and Permission Check Bypassed - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a complete no-op (`return nil, nil`). It performs no permission check and makes no state change. This means: (1) any unprivileged user can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission system; and (2) the bridge circuit breaker can never be activated — the bridge cannot be disabled in an emergency.

### Finding Description

The `TurnBridge` gRPC handler is registered in the Cronos module's `MsgServer` and is reachable by any on-chain transaction sender:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, the sibling handler, which correctly enforces the permission system before acting:

```go
func (k msgServer) UpdateTokenMapping(...) (...) {
    if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    ...
}
``` [2](#0-1) 

The permission system defines `CanTurnBridge` as a distinct bit-flag that must be held by the sender or the `CronosAdmin`: [3](#0-2) 

The proto definition and CLI both expose `MsgTurnBridge` as a live, callable transaction type: [4](#0-3) [5](#0-4) 

Two concrete failures result:

**1. Permission bypass**: Because there is no `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` guard, any unprivileged address can submit `MsgTurnBridge` and receive a `code: 0` success response. The integration test explicitly expects this to fail for a non-permissioned sender (`assert rsp["code"] != 0`), but the no-op handler returns success unconditionally. [6](#0-5) 

**2. Bridge circuit breaker permanently non-functional**: The handler never writes any bridge-enabled/disabled state to the KV store. No EVM hook or keeper function reads a bridge-enabled flag that this handler would set. The bridge can therefore never be disabled through `MsgTurnBridge`, regardless of who calls it. The integration test expects that after a successful `turn_bridge("false")` call, subsequent bridge operations revert — but since no state is changed, they continue to succeed. [7](#0-6) 

### Impact Explanation

**High — Bypass of Cronos admin/bridge authorization checks.**

The `CanTurnBridge` permission exists precisely to allow a trusted operator to halt the gravity bridge in an emergency (e.g., a discovered exploit). The no-op handler means:
- Any unprivileged user can call `MsgTurnBridge` and receive a success response, bypassing the permission gate entirely.
- The bridge circuit breaker is permanently non-functional. Even the `CronosAdmin` cannot disable the bridge through the intended mechanism. In an emergency, bridge operations (token transfers to Ethereum via `send_to_evm_chain` / `send_to_ethereum` EVM hooks) continue unimpeded.

This directly matches the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."*

### Likelihood Explanation

The vulnerability is reachable by any address that can submit a Cosmos transaction. No special privileges, leaked keys, or cryptographic breaks are required. The `MsgTurnBridge` message type is fully registered and callable on-chain. The permission bypass is unconditional.

### Recommendation

Restore the `TurnBridge` handler to a correct implementation:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)

    // Enforce CanTurnBridge permission
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }

    // Persist the bridge-enabled state
    params := k.GetParams(ctx)
    params.EnableGravity = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }

    return &types.MsgTurnBridgeResponse{}, nil
}
```

Additionally, all EVM hooks that process bridge-out events (`__CronosSendToEvmChain`, `__CronosSendToEthereum`) must read and enforce the bridge-enabled flag before processing, analogous to how `whenNotPaused` guards user-accessible functions in the external report.

### Proof of Concept

1. Any unprivileged address submits `MsgTurnBridge{Sender: attacker, Enable: false}`.
2. The handler at `x/cronos/keeper/msg_server.go:85` returns `nil, nil` — the transaction succeeds with `code: 0`.
3. No bridge-enabled state is written to the KV store.
4. A user calls `send_to_evm_chain(...)` on a CRC21 contract; the EVM hook fires and processes the bridge-out transfer normally — the "disabled" bridge has no effect.
5. The `CronosAdmin` is equally unable to disable the bridge: even a correctly permissioned `MsgTurnBridge` call is silently discarded by the no-op handler.

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

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```

**File:** x/cronos/client/cli/tx.go (L264-290)
```go
// CmdTurnBridge returns a CLI command handler for enable or disable the bridge
func CmdTurnBridge() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "turn-bridge [true/false]",
		Short: "Turn Bridge",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			enable, err := strconv.ParseBool(args[0])
			if err != nil {
				return err
			}
			msg := types.NewMsgTurnBridge(clientCtx.GetFromAddress().String(), enable)
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
```

**File:** integration_tests/test_gravity.py (L661-662)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"
```

**File:** integration_tests/test_gravity.py (L668-674)
```python
    if gravity.cronos.enable_auto_deployment:
        # send it back to erc20, should fail
        tx = crc21_contract.functions.send_to_evm_chain(
            ADDRS["validator"], amount, 1, 0, b""
        ).build_transaction({"from": ADDRS["community"]})
        txreceipt = send_transaction(cronos_w3, tx, KEYS["community"])
        assert txreceipt.status == 0, "should fail"
```
