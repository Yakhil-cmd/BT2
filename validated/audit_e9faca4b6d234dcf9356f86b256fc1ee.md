### Title
`TurnBridge` Message Handler Is a No-Op Stub, Permanently Disabling the Bridge Pause Mechanism and Bypassing `CanTurnBridge` Permission Enforcement — (File: `x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` gRPC message handler in Cronos's `x/cronos` module is implemented as a stub that unconditionally returns `nil, nil`. It performs no permission check and writes no state. As a result: (1) any unprivileged caller can invoke `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission guard; and (2) the bridge-enabled state is never updated, so the bridge can never actually be disabled. The downstream consequence is that `ConvertVouchers` / `ConvertVouchersToEvmCoins` — which mints CRC20/native EVM tokens — continues to operate unconditionally even when an operator intends to halt the bridge in an emergency.

---

### Finding Description

`x/cronos/keeper/msg_server.go` lines 84–87:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The handler is a complete stub. Compare with `UpdateTokenMapping`, which correctly gates on `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`: [2](#0-1) 

The permission system defines `CanTurnBridge` as a distinct bit-flag and the `HasPermission` helper enforces it: [3](#0-2) 

The integration test `test_gravity_turn_bridge` explicitly asserts that an unauthorized caller receives a non-zero error code, confirming the intent that `TurnBridge` must be permission-gated: [4](#0-3) 

Because the handler writes no state, `ConvertVouchersToEvmCoins` — which mints native EVM tokens (basecro) and calls `mint_by_cronos_module` on CRC21 contracts — has no bridge-enabled flag to check and will always succeed: [5](#0-4) 

The IBC conversion middleware's `OnRecvPacket` also calls `ConvertVouchersToEvmCoins` unconditionally on every inbound IBC packet whose denom is mapped: [6](#0-5) 

The `MsgConvertVouchers` message server handler similarly calls `ConvertVouchersToEvmCoins` with no bridge-state guard: [7](#0-6) 

---

### Impact Explanation

Two distinct impacts apply:

**High — Bypass of bridge authorization checks**: Because `TurnBridge` returns `nil, nil` without calling `HasPermission`, any unprivileged address can submit `MsgTurnBridge` and receive a success response. The `CanTurnBridge` permission guard is entirely bypassed.

**High — Permanent inability to halt bridge/conversion flows**: The bridge-enabled state is never written, so the bridge can never be disabled. In an emergency (e.g., a vulnerability in a mapped CRC21 contract, an accounting discrepancy, or an IBC channel exploit), operators have no on-chain mechanism to stop `ConvertVouchers` or the IBC middleware from continuing to mint CRC20/native EVM tokens. This is the direct Cronos analog to H-09: just as Illuminate's `mint` ignored the market-paused flag, Cronos's conversion path has no bridge-enabled flag to check because the setter is a no-op.

---

### Likelihood Explanation

The stub is reachable by any address that can submit a Cosmos transaction — no special privilege is required. The `MsgTurnBridge` message is registered in the codec and exposed via the CLI (`CmdTurnBridge`). The conversion paths (`MsgConvertVouchers`, IBC middleware `OnRecvPacket`) are reachable by any user holding IBC vouchers or mapped tokens. [8](#0-7) 

---

### Recommendation

1. Implement `TurnBridge` to check `HasPermission(ctx, msg.GetSigners(), CanTurnBridge)` and reject unauthorized callers.
2. Persist the `enable` flag to module params (e.g., a `BridgeEnabled` field in `Params`).
3. Add a bridge-enabled guard at the top of `ConvertVouchersToEvmCoins` and in `IBCConversionModule.OnRecvPacket` so that conversion/minting is rejected when the bridge is disabled.

---

### Proof of Concept

1. Any address `A` (no `CanTurnBridge` permission) submits `MsgTurnBridge{Sender: A, Enable: false}`.
2. The stub handler returns success (`nil, nil`) — no error, no state change.
3. The bridge-enabled state remains unchanged (effectively always enabled).
4. `A` (or any other address) submits `MsgConvertVouchers` with IBC vouchers; `ConvertVouchersToEvmCoins` mints CRC20/native EVM tokens without restriction.
5. Even if an operator with `CanTurnBridge` permission submits the same message intending to halt the bridge in an emergency, the outcome is identical — the bridge cannot be stopped.

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-45)
```go
func (k msgServer) ConvertVouchers(goCtx context.Context, msg *types.MsgConvertVouchers) (*types.MsgConvertVouchersResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	err := k.ConvertVouchersToEvmCoins(ctx, msg.Address, msg.Coins)
	if err != nil {
		return nil, err
	}

	// emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		types.NewConvertVouchersEvent(msg.Address, msg.Coins),
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)

	return &types.MsgConvertVouchersResponse{}, nil
}
```

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

**File:** integration_tests/test_gravity.py (L661-665)
```python
    rsp = cli.turn_bridge("false", from_="community")
    assert rsp["code"] != 0, "should not have the permission"

    rsp = cli.turn_bridge("false", from_="validator")
    assert rsp["code"] == 0, rsp["raw_log"]
```

**File:** x/cronos/keeper/ibc.go (L21-65)
```go
func (k Keeper) ConvertVouchersToEvmCoins(ctx sdk.Context, from string, coins sdk.Coins) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}

	params := k.GetParams(ctx)
	evmParams := k.GetEvmParams(ctx)
	for _, c := range coins {
		switch c.Denom {
		case params.IbcCroDenom:
			if params.IbcCroDenom == "" {
				return errorsmod.Wrap(types.ErrIbcCroDenomEmpty, "ibc is disabled")
			}

			// Send ibc tokens to escrow address
			err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, acc, types.ModuleName, sdk.NewCoins(c))
			if err != nil {
				return err
			}
			// Compute new amount, because basecro is a 8 decimals token, we need to multiply by 10^10 to make it
			// a 18 decimals token
			amount18dec := sdk.NewCoin(evmParams.EvmDenom, c.Amount.Mul(sdkmath.NewIntFromBigInt(types.TenPowTen)))

			// Mint new evm tokens
			if err := k.bankKeeper.MintCoins(
				ctx, types.ModuleName, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

			// Send evm tokens to receiver
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, acc, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
	}
```

**File:** x/cronos/middleware/conversion_middleware.go (L105-147)
```go
// OnRecvPacket implements the IBCModule interface.
func (im IBCConversionModule) OnRecvPacket(
	ctx sdk.Context,
	channelVersion string,
	packet channeltypes.Packet,
	relayer sdk.AccAddress,
) exported.Acknowledgement {
	cacheCtx, commit := ctx.CacheContext()
	ack := im.app.OnRecvPacket(cacheCtx, channelVersion, packet, relayer)
	if !ack.Success() {
		// Underlying transfer failed: discard cacheCtx writes and return the
		// failure ack. Committing would persist a half-applied transfer.
		return ack
	}
	data, err := transferTypes.UnmarshalPacketData(packet.GetData(), channelVersion, "")
	if err != nil {
		return channeltypes.NewErrorAcknowledgement(errors.Wrap(sdkerrors.ErrUnknownRequest,
			"cannot unmarshal ICS-20 transfer packet data in middleware"))
	}
	denom := im.getIbcDenomFromPacketAndData(packet, data.Token)
	if im.canBeConverted(cacheCtx, denom) {
		transferAmount, ok := sdkmath.NewIntFromString(data.Token.Amount)
		if !ok {
			return channeltypes.NewErrorAcknowledgement(errors.Wrapf(
				transferTypes.ErrInvalidAmount,
				"unable to parse transfer amount (%s) into sdk.Int in middleware",
				data.Token.Amount,
			))
		}
		token := sdk.NewCoin(denom, transferAmount)
		if err := im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, sdk.NewCoins(token)); err != nil {
			im.cronoskeeper.Logger(ctx).Error(
				"failed to convert vouchers on recv",
				"denom", denom,
				"receiver", data.Receiver,
				"error", err,
			)
			return channeltypes.NewErrorAcknowledgement(err)
		}
	}
	commit()
	return ack
}
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
