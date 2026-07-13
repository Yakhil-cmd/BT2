### Title
`TurnBridge` Is a No-Op Stub — Bridge Circuit Breaker Permanently Broken and Authorization Check Absent - (File: `x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler, which is the sole on-chain mechanism to enable or disable the Gravity bridge as an emergency circuit breaker, is implemented as a stub that unconditionally returns `nil, nil`. It performs no authorization check and writes no state. Any unprivileged address can submit a `MsgTurnBridge` transaction and receive a success response, while the bridge enable/disable state is never actually changed.

### Finding Description
The `TurnBridge` handler in `x/cronos/keeper/msg_server.go` reads:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The proto definition and CLI both expose a fully-formed `MsgTurnBridge{Sender, Enable}` message: [2](#0-1) [3](#0-2) 

The permissions system defines `CanTurnBridge` as a distinct permission bit that is supposed to gate this operation: [4](#0-3) 

The ADR-009 architecture document explicitly describes `MsgTurnBridge` as the circuit-breaker for the Gravity bridge module: [5](#0-4) 

Two bugs are present simultaneously:

1. **Missing authorization check**: Every other privileged handler (`UpdateTokenMapping`, `UpdatePermissions`, `StoreBlockList`) checks the caller's permission or admin status before proceeding. `TurnBridge` skips this entirely, so any unprivileged address can submit the message and receive `code: 0`. [6](#0-5) 

2. **No state write**: The handler never reads `msg.Enable`, never calls `SetParams`, and never updates any bridge-enabled flag. The `Params` struct has no `BridgeEnabled` field, and the stub writes nothing, so the bridge state is permanently frozen at its genesis value. [7](#0-6) 

This is the direct Cronos analog of the external report's bug: a function that is supposed to update a critical permission/state flag but, due to a coding error (here, a stub body instead of a self-comparison), silently does nothing.

### Impact Explanation
- **Auth bypass (High)**: The `CanTurnBridge` permission check is completely absent. Any unprivileged address can call `MsgTurnBridge` and receive a success response, bypassing the bridge authorization gate.
- **Permanent bridge circuit-breaker failure (High)**: The bridge can never be disabled on-chain. In an emergency (e.g., a bridge exploit in progress), the admin or a `CanTurnBridge`-permissioned address has no way to halt bridge operations via the intended mechanism. Bridge/conversion flows that should be stoppable remain permanently active.

### Likelihood Explanation
The `TurnBridge` RPC is registered, the CLI command is shipped, and the `CanTurnBridge` permission bit is documented and assignable. Any operator or user who submits a `MsgTurnBridge` transaction will observe a success response while the bridge state is unchanged. The stub is reachable by any unprivileged address with no preconditions.

### Recommendation
Implement `TurnBridge` with:
1. A `CanTurnBridge` permission check mirroring the pattern in `UpdateTokenMapping`.
2. A bridge-enabled boolean stored in module params (add `EnableGravityBridge bool` to `Params`) or a dedicated KV key.
3. A state write that persists `msg.Enable` and is read by the Gravity bridge hooks before processing inbound/outbound transfers.

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.EnableGravityBridge = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

### Proof of Concept
1. Submit `MsgTurnBridge{Sender: <any_unprivileged_address>, Enable: false}` on-chain.
2. Observe `code: 0` in the response — no authorization error is returned.
3. Query module params; no bridge-enabled flag changes.
4. Attempt a Gravity bridge transfer; it succeeds, confirming the bridge was never disabled.
5. Repeat with `Enable: true` from the same unprivileged address — same result, confirming the auth check is absent in both directions.

### Citations

**File:** x/cronos/keeper/msg_server.go (L69-82)
```go
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

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
```

**File:** docs/architecture/adr-009.md (L36-38)
```markdown
- Assign to each "restricted" messages in Cronos a permission (integer value) and create in Cronos module a mapping between addresses and permissions that is stored in memory. For now, there are only two messages that require permission : MsgUpdateTokenMapping and MsgTurnBridge.
- Create a msg type "MsgUpdatePermissions" that only admin can use and allow to update the address permission mapping.
- Change the logic to always check for the permission before processing the restricted messages.
```

**File:** x/cronos/types/cronos.pb.go (L27-36)
```go
type Params struct {
	IbcCroDenom string `protobuf:"bytes,1,opt,name=ibc_cro_denom,json=ibcCroDenom,proto3" json:"ibc_cro_denom,omitempty" yaml:"ibc_cro_denom,omitempty"`
	IbcTimeout  uint64 `protobuf:"varint,2,opt,name=ibc_timeout,json=ibcTimeout,proto3" json:"ibc_timeout,omitempty"`
	// the admin address who can update token mapping
	CronosAdmin          string `protobuf:"bytes,3,opt,name=cronos_admin,json=cronosAdmin,proto3" json:"cronos_admin,omitempty"`
	EnableAutoDeployment bool   `protobuf:"varint,4,opt,name=enable_auto_deployment,json=enableAutoDeployment,proto3" json:"enable_auto_deployment,omitempty"`
	MaxCallbackGas       uint64 `protobuf:"varint,5,opt,name=max_callback_gas,json=maxCallbackGas,proto3" json:"max_callback_gas,omitempty"`
	// the authorized contract addresses for the SendCroToIbc hook; empty list disables the hook
	CroBridgeContractAddresses []string `protobuf:"bytes,6,rep,name=cro_bridge_contract_addresses,json=croBridgeContractAddresses,proto3" json:"cro_bridge_contract_addresses,omitempty"`
}
```
