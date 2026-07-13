### Title
`MsgTurnBridge` Handler Is a No-Op: Bridge Circuit Breaker Permanently Non-Functional and Permission-Free — (File: `x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is implemented as a literal no-op (`return nil, nil`). It performs no permission check and modifies no state. Any unprivileged address can call `MsgTurnBridge` and receive a success response (code 0), while the admin's ability to disable the gravity bridge in an emergency is permanently broken. This is a direct analog to the "ineffective whitelist" class: the permission system for bridge control is fully defined but is entirely absent from the one handler that exercises it.

---

### Finding Description

`MsgTurnBridge` is the emergency circuit breaker for the Cronos gravity bridge. The permission infrastructure for it is fully built out:

- `CanTurnBridge` constant is defined in `x/cronos/keeper/permissions.go`
- `HasPermission` is used correctly in `UpdateTokenMapping` to gate that handler
- `QueryPermissionsResponse` exposes `CanTurnBridge` as a queryable field
- `MsgUpdatePermissions` allows the admin to grant `CanTurnBridge` to other addresses
- Integration tests in `integration_tests/test_gravity.py` explicitly assert that an unauthorized caller gets `code != 0` and that after a successful `turn_bridge("false")` call, bridge operations revert

The actual handler implementation, however, is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Compare this to `UpdateTokenMapping`, which correctly gates on `HasPermission`:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

The `CanTurnBridge` permission bit is defined alongside `CanChangeTokenMapping` but is never consumed: [3](#0-2) 

The proto definition and CLI command are fully wired: [4](#0-3) [5](#0-4) 

The integration test confirms the intended behavior that is absent: [6](#0-5) 

---

### Impact Explanation

**High — Bypass of Cronos admin/governance bridge control authority.**

Two distinct impacts compound:

1. **Unprivileged bypass of permission check**: Any address, with no `CanTurnBridge` permission, can submit `MsgTurnBridge` and receive a success response (`code == 0`). The `CanTurnBridge` permission check is completely absent. This directly mirrors the LensHub whitelist finding: a permission gate exists in the system design but is not enforced at the execution boundary.

2. **Permanent non-functionality of the bridge circuit breaker**: Even the legitimate admin or a permissioned address cannot turn off the bridge, because the handler writes nothing to state. In an active bridge exploit, the admin's emergency action silently succeeds on-chain while the bridge continues processing all outbound transfers. This is a permanent inability for the authorized party to exercise their governance-granted bridge control.

---

### Likelihood Explanation

The entry path is trivially reachable: `MsgTurnBridge` is a standard proto-defined Cosmos SDK message, exposed via gRPC and CLI, with no ante-handler guard. Any funded address can broadcast it. The integration test suite (`test_gravity_turn_bridge`) would fail on three assertions with the current implementation, confirming this is not a latent edge case but a broken core feature.

---

### Recommendation

Implement `TurnBridge` to:
1. Check `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and return `ErrUnauthorized` on failure.
2. Persist the `enable` flag to the KV store (e.g., under a `KeyPrefixBridgeEnabled` key).
3. Have the gravity bridge EVM hook handlers (`SendToEvmChain`, `SendToIbc` for gravity-originated tokens) read this flag and reject processing when the bridge is disabled.

---

### Proof of Concept

```
# Step 1: Unprivileged user calls TurnBridge — succeeds with code 0, no permission check
cronosd tx cronos turn-bridge false --from unprivileged_user
# → code: 0  (should be non-zero; CanTurnBridge not held)

# Step 2: Admin calls TurnBridge to disable bridge in emergency
cronosd tx cronos turn-bridge false --from admin
# → code: 0  (succeeds, but bridge state is unchanged)

# Step 3: Bridge operation proceeds normally — circuit breaker had no effect
# Any user can still call send_to_evm_chain on a CRC21 contract and the
# EVM hook processes the outbound transfer, because no "bridge enabled" flag
# was ever written to state.
```

The no-op at `x/cronos/keeper/msg_server.go:85-86` is the sole root cause. The permission constants, the `HasPermission` helper, and the integration test assertions all exist and are correct — only the handler body is missing.

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

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
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

**File:** integration_tests/test_gravity.py (L660-680)
```python
    # turn off bridge
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
    wait_for_new_blocks(cli, 1)

    if gravity.cronos.enable_auto_deployment:
        # send it back to erc20, should fail
        tx = crc21_contract.functions.send_to_evm_chain(
            ADDRS["validator"], amount, 1, 0, b""
        ).build_transaction({"from": ADDRS["community"]})
        txreceipt = send_transaction(cronos_w3, tx, KEYS["community"])
        assert txreceipt.status == 0, "should fail"
    else:
        # send back the gravity native tokens, should fail
        rsp = cli.send_to_ethereum(
            ADDRS["validator"], f"{amount}{denom}", f"0{denom}", from_="community"
        )
        assert rsp["code"] == 3, rsp["raw_log"]
```
