### Title
`TurnBridge` Handler Is a No-Op, Permanently Bypassing Bridge Disable Authority — (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a complete no-op: it returns `nil, nil` without performing any permission check or writing any state. As a result, the Gravity Bridge can never be disabled by the admin, and any unprivileged user can continue to bridge tokens to Ethereum even after an authorized admin has submitted a `MsgTurnBridge{Enable: false}` transaction.

### Finding Description

`MsgTurnBridge` is the on-chain mechanism for an authorized admin to halt the Gravity Bridge. The `CanTurnBridge` permission bit exists precisely for this purpose, and the integration test `test_gravity_turn_bridge` documents the expected invariant: after a successful `turn_bridge false`, any subsequent `send_to_evm_chain` call must revert.

The actual handler, however, is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this with `UpdateTokenMapping`, which correctly gates on `CanChangeTokenMapping` and then writes state:

```go
if !k.HasPermission(ctx, []sdk.AccAddress{...}, CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, ...)
}
``` [2](#0-1) 

The `TurnBridge` handler:
1. Performs **no permission check** — any address can submit the message and receive a success response.
2. **Writes no state** — the bridge-enabled flag is never stored in the KV store or params.
3. Returns `nil, nil` unconditionally, so the Cosmos SDK marks the transaction as successful.

Because no bridge-enabled flag is ever written, any downstream check that would gate `__CronosSendToEvmChain` processing on that flag will always see the default (enabled) value.

The `CanTurnBridge` permission constant is defined but is never consulted by the handler:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization check.**

An authorized admin submits `MsgTurnBridge{Enable: false}`. The transaction is accepted and returns code 0, giving the admin false confidence that the bridge is now halted. Because no state is written, the bridge remains permanently enabled. Any unprivileged user can immediately call `send_to_evm_chain` on a CRC21 contract:

```solidity
function send_to_evm_chain(address recipient, uint amount, uint chain_id, uint bridge_fee, bytes calldata extraData) external {
    if (isSource) {
        transferFrom(msg.sender, module_address, add(amount, bridge_fee));
    } else {
        unsafe_burn(msg.sender, add(amount, bridge_fee));
    }
    emit __CronosSendToEvmChain(msg.sender, recipient, chain_id, amount, bridge_fee, extraData);
}
``` [4](#0-3) 

The emitted `__CronosSendToEvmChain` event is processed by the Gravity Bridge module, which will batch and relay the transfer to Ethereum. The admin's disable action has zero effect on this flow.

Additionally, because the handler performs no permission check, **any** address (not just one holding `CanTurnBridge`) can submit `MsgTurnBridge` and receive a success response, further undermining the permission model.

### Likelihood Explanation

The bypass requires no special attacker capability. Any user who wishes to bridge tokens after an admin disable attempt simply calls `send_to_evm_chain` as normal. The admin's action is silently ignored. The likelihood is **certain** whenever an admin attempts to use `TurnBridge` to halt the bridge in an emergency.

### Recommendation

Implement `TurnBridge` to:
1. Verify the sender holds the `CanTurnBridge` permission via `k.HasPermission`.
2. Persist the bridge-enabled flag (e.g., as a field in `Params` or a dedicated KV key).
3. Ensure the EVM hook that processes `__CronosSendToEvmChain` reads this flag and returns an error when the bridge is disabled, causing the EVM transaction to revert.

### Proof of Concept

1. Unprivileged user holds CRC21 tokens on Cronos.
2. Admin submits `MsgTurnBridge{Sender: admin, Enable: false}` — transaction succeeds (code 0), but the handler body is `return nil, nil`; no state is written.
3. Unprivileged user calls `crc21.send_to_evm_chain(recipient, amount, chainId, 0, "")`.
4. The contract burns/transfers tokens and emits `__CronosSendToEvmChain`.
5. The Gravity Bridge module processes the event and batches the outgoing transfer — the bridge-disabled flag was never set, so no guard fires.
6. Tokens are relayed to Ethereum, bypassing the admin's intended halt. [1](#0-0) [3](#0-2) [4](#0-3)

### Citations

**File:** x/cronos/keeper/msg_server.go (L60-82)
```go
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)
	return &types.MsgTransferTokensResponse{}, nil
}

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

**File:** contracts/src/ModuleCRC21.sol (L70-77)
```text
    function send_to_evm_chain(address recipient, uint amount, uint chain_id, uint bridge_fee, bytes calldata extraData) external {
        if (isSource) {
            transferFrom(msg.sender, module_address, add(amount, bridge_fee));
        } else {
            unsafe_burn(msg.sender, add(amount, bridge_fee));
        }
        emit __CronosSendToEvmChain(msg.sender, recipient, chain_id, amount, bridge_fee, extraData);
    }
```
