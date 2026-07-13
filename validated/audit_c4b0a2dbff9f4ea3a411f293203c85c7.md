### Title
`TurnBridge` Handler is a No-Op — Bridge Cannot Be Disabled and `CanTurnBridge` Permission Check is Absent - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler returns `nil, nil` unconditionally, performing no authorization check and storing no state. This creates two compounding issues that are directly analogous to H-01's asymmetric-check pattern: (1) any unprivileged caller can invoke `TurnBridge` without the `CanTurnBridge` permission that the codebase explicitly defines for this purpose, and (2) the bridge can never actually be disabled — all bridge-exit operations (`send_to_ibc`, `send_to_evm_chain`, `ConvertVouchers`, `TransferTokens`) proceed unconditionally because no bridge-enabled state is ever written or read. An admin who calls `TurnBridge(false)` receives a success response while the bridge continues operating, creating a false sense of security.

### Finding Description

`x/cronos/keeper/msg_server.go` lines 84–87:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare with `UpdateTokenMapping`, which correctly gates on `CanChangeTokenMapping`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The `CanTurnBridge` permission constant is defined alongside `CanChangeTokenMapping` in `permissions.go` but is never referenced anywhere in the keeper:

```go
const (
    CanChangeTokenMapping uint64 = 1 << iota // 1
    CanTurnBridge                             // 2
    All = CanChangeTokenMapping | CanTurnBridge // 3
)
``` [3](#0-2) 

No bridge-enabled flag is stored in module params. The four module params are `IbcCroDenom`, `IbcTimeout`, `CronosAdmin`, and `EnableAutoDeployment` — there is no `BridgeEnabled` field. [4](#0-3) 

All bridge-exit paths — the `SendToIbcHandler`, the `SendToEvmChainHandler` EVM hooks, `ConvertVouchers`, and `TransferTokens` — execute unconditionally without consulting any bridge-enabled state. [5](#0-4) 

The asymmetry that maps directly to H-01:

| H-01 (BranchPort) | Cronos analog |
|---|---|
| `toggleStrategyToken(false)` stores disabled flag | `TurnBridge(false)` stores nothing (no-op) |
| `manage()` skips the enabled check → withdrawal still works | All bridge-exit ops skip any bridge-enabled check → bridge still works |
| `replenishReserves()` checks the flag → forced return blocked | Admin's `TurnBridge(false)` call returns success → admin believes bridge is off |

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization checks.**

1. **Permission bypass (unprivileged path):** Any address, without `CanTurnBridge`, can submit a `MsgTurnBridge` transaction. It succeeds (zero error) and emits no rejection event. The `CanTurnBridge` permission is rendered dead code.

2. **Permanent bridge-disable bypass:** An authorized admin who calls `TurnBridge(false)` during a security incident receives a success response. Because no state is written, every subsequent `send_to_ibc`, `send_to_evm_chain`, `ConvertVouchers`, and `TransferTokens` call continues to execute normally. The admin's bridge-shutdown intent is silently discarded, and the bridge remains live indefinitely.

The second impact is the critical one: the admin's only mechanism to halt bridge asset flows in an emergency is completely non-functional, matching the H-01 pattern where the admin's "disable" action leaves one path (withdrawal) open while the recovery path (replenish) is blocked.

### Likelihood Explanation

The `MsgTurnBridge` RPC is a registered, publicly reachable transaction surface. [6](#0-5)  Any user can submit it at zero cost beyond gas. The admin path (calling `TurnBridge(false)` to halt the bridge) is the expected operational response to a bridge exploit; the no-op silently defeats it every time it is invoked.

### Recommendation

1. **Add the authorization check** to `TurnBridge` consistent with `UpdateTokenMapping`:
   ```go
   if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
       return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
   }
   ```

2. **Persist bridge-enabled state** — add a `BridgeEnabled bool` field to module `Params` (or a dedicated KV key) and write it in the handler.

3. **Guard all bridge-exit paths** — `SendToIbcHandler.Handle`, `SendToEvmChainHandler.Handle`, `ConvertVouchers`, and `TransferTokens` must each read the bridge-enabled flag and return an error when the bridge is disabled, mirroring the fix recommended in H-01 for `manage()`.

### Proof of Concept

1. Admin observes a bridge exploit and submits `MsgTurnBridge{Sender: admin, Enable: false}`.
2. The handler at `msg_server.go:85–86` returns `nil, nil` — no state is written, no error is returned.
3. The admin's client receives a successful transaction receipt and believes the bridge is off.
4. An attacker submits `send_to_evm_chain(...)` on a CRC21 contract; `SendToEvmChainHandler.Handle` executes without consulting any bridge-enabled flag and processes the transfer normally.
5. The bridge continues to drain funds while the admin believes it is disabled. [1](#0-0) [3](#0-2)

### Citations

**File:** x/cronos/keeper/msg_server.go (L72-75)
```go
	// check permission
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
```

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** x/cronos/keeper/permissions.go (L14-16)
```go
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
```

**File:** x/cronos/spec/07_params.md (L9-15)
```markdown
| Key                    | Type   | Default Value                                                |
| ---------------------- | ------ | ------------------------------------------------------------ |
| `IbcCroDenom`          | string | `"ibc/6B5A664BF0AF4F71B2F0BAA33141E2F1321242FBD5D19762F541EC971ACB0865"` |
| `IbcTimeout`           | uint64 | `86400000000000`                                             |
| `CronosAdmin`          | string | `""`                                                         |
| `EnableAutoDeployment` | bool   | `false`                                                      |

```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L86-97)
```go
func (h SendToIbcHandler) handle(
	ctx sdk.Context,
	contract common.Address,
	senderAddress common.Address,
	recipient string,
	amountInt *big.Int,
	id *big.Int,
) error {
	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}
```

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
```
