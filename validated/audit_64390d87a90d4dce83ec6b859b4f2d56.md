### Title
`TurnBridge` Is a No-Op Stub: Bridge-Disable Mechanism Completely Bypassed and Non-Functional — (`File: x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` gRPC handler, which is the designated mechanism for an authorized operator to disable the Cronos bridge in an emergency, is implemented as a no-op stub that performs no permission check and changes no state. Any unprivileged user can call it and receive a success response. Because no bridge-active state is ever written, `ConvertVouchers`, `TransferTokens`, and all EVM-log bridge handlers (`SendToIbcHandler`, `SendToIbcV2Handler`, `SendCroToIbcHandler`) proceed unconditionally, with no guard that could ever be tripped by a bridge-disable action.

### Finding Description

`TurnBridge` in `msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

It does two things wrong simultaneously:

1. **No permission check.** The `CanTurnBridge` permission constant is defined and the `HasPermission` helper exists, but neither is called here. Every other privileged handler (`UpdateTokenMapping`, `UpdatePermissions`, `StoreBlockList`) calls `HasPermission` or checks `CronosAdmin` before acting. `TurnBridge` does not. [2](#0-1) [3](#0-2) 

2. **No state mutation.** The function returns `nil, nil` without writing any `bridge_active` flag or equivalent to the store. The `Params` struct has no such field, so there is nothing for downstream callers to check. [4](#0-3) 

Because no bridge-active state is ever set, `ConvertVouchers` and `TransferTokens` in `msg_server.go` proceed directly to `ConvertVouchersToEvmCoins` and `IbcTransferCoins` with no bridge-state guard: [5](#0-4) 

The EVM-log handlers (`SendToIbcHandler.handle`, `SendToIbcV2Handler.Handle`, `SendCroToIbcHandler.Handle`) similarly call `IbcTransferCoins` or `bankKeeper.SendCoins` with no bridge-active check: [6](#0-5) [7](#0-6) 

The IBC conversion middleware (`OnRecvPacket`, `OnAcknowledgementPacket`, `OnTimeoutPacket`) also calls `ConvertVouchersToEvmCoins` / `OnRecvVouchers` unconditionally: [8](#0-7) 

### Impact Explanation

**High — Bypass of Cronos bridge authorization checks and permanent inability to disable bridge/conversion flows.**

- Any unprivileged address can submit `MsgTurnBridge` and receive a success response, bypassing the `CanTurnBridge` permission entirely.
- Because the stub never writes state, the bridge-disable mechanism is permanently non-functional. Even a correctly-permissioned admin call produces no effect.
- In an emergency (e.g., a critical vulnerability in the IBC conversion or EVM-hook path is discovered), the designated circuit-breaker cannot be activated. Token minting, burning, and IBC transfers via `ConvertVouchers`, `TransferTokens`, and all EVM-log bridge handlers will continue unimpeded.

This maps directly to the allowed High impact: *"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks"* and *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows … under normal network assumptions."*

### Likelihood Explanation

The `MsgTurnBridge` message is registered, the CLI command `CmdTurnBridge` is wired, and the `CanTurnBridge` permission constant is defined — all indicating the feature was intended to be functional. The stub body is the only missing piece, making this a straightforward oversight rather than a design decision. Any user who submits the transaction will observe a success response, confirming the auth bypass is reachable without any special privilege. [9](#0-8) [10](#0-9) 

### Recommendation

1. **Implement `TurnBridge` properly.** Add a `bridge_active bool` field to `Params`, persist it in the store, and write the actual toggle logic:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.BridgeActive = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

2. **Add a bridge-active guard** at the top of `ConvertVouchers`, `TransferTokens`, and each EVM-log handler (`SendToIbcHandler.handle`, `SendCroToIbcHandler.Handle`) so they return an error when `bridge_active == false`.

3. **Add the same guard** in `IBCConversionModule.OnRecvPacket` so that incoming IBC voucher auto-conversion is also halted when the bridge is disabled.

### Proof of Concept

1. Deploy Cronos with default params (no `bridge_active` field, `TurnBridge` is a no-op).
2. As any unprivileged address, submit `MsgTurnBridge{Sender: attacker, Enable: false}`.
3. Observe the transaction succeeds (`code: 0`) — no permission error is returned.
4. Observe that `ConvertVouchers` and `TransferTokens` still succeed — no bridge-disabled error is returned.
5. The bridge-disable mechanism is confirmed non-functional: the attacker's call succeeded without `CanTurnBridge` permission, and legitimate admin calls are equally ineffective.

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-65)
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

func (k msgServer) TransferTokens(goCtx context.Context, msg *types.MsgTransferTokens) (*types.MsgTransferTokensResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	// TODO change the msg to be able to specify the channel id
	// Only sending non source token is supported at the moment
	err := k.IbcTransferCoins(ctx, msg.From, msg.To, msg.Coins, "")
	if err != nil {
		return nil, err
	}

	// emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		types.NewTransferTokensEvent(msg.From, msg.To, msg.Coins),
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
		),
	},
	)
	return &types.MsgTransferTokensResponse{}, nil
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

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L86-134)
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

	if !types.IsValidIBCDenom(denom) && !types.IsValidCronosDenom(denom) {
		return fmt.Errorf("the native token associated with the contract %s is neither an ibc voucher or a cronos token", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	sender := sdk.AccAddress(senderAddress.Bytes())
	amount := sdkmath.NewIntFromBigInt(amountInt)
	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))

	var err error
	if types.IsSourceCoin(denom) {
		// it is a source token, we need to mint coins
		if err = h.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
		// send the coin to the user
		if err = h.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sender, coins); err != nil {
			return err
		}
	} else {
		// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
		if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
			return err
		}
	}

	channelId := ""
	if id != nil {
		channelId = "channel-" + id.String()
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins, channelId); err != nil {
		return err
	}
	return nil
}
```

**File:** x/cronos/keeper/evmhandlers/send_cro_to_ibc.go (L68-104)
```go
func (h SendCroToIbcHandler) Handle(
	ctx sdk.Context,
	contract common.Address,
	topics []common.Hash,
	data []byte,
	_ func(contractAddress common.Address, logSig common.Hash, logData []byte),
) error {
	authorizedBridges := h.cronosKeeper.GetParams(ctx).CroBridgeContractAddresses
	if !slices.ContainsFunc(authorizedBridges, func(addr string) bool {
		return common.HexToAddress(addr) == contract
	}) {
		return fmt.Errorf("contract %s is not authorized to use SendCroToIbc hook", contract)
	}

	unpacked, err := SendCroToIbcEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Error("log signature matches but failed to decode", "error", err)
		return nil
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	sender := sdk.AccAddress(unpacked[0].(common.Address).Bytes())
	recipient := unpacked[1].(string)
	amount := sdkmath.NewIntFromBigInt(unpacked[2].(*big.Int))
	evmDenom := h.cronosKeeper.GetEvmParams(ctx).EvmDenom
	coins := sdk.NewCoins(sdk.NewCoin(evmDenom, amount))
	// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
	if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
		return err
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins, ""); err != nil {
		return err
	}
	return nil
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

**File:** x/cronos/types/codec.go (L23-29)
```go
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgConvertVouchers{},
		&MsgTransferTokens{},
		&MsgUpdateTokenMapping{},
		&MsgTurnBridge{},
		&MsgUpdatePermissions{},
	)
```
