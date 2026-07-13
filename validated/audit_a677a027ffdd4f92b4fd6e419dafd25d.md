### Title
`MsgTurnBridge` Handler Is a No-Op — Bridge Disable Mechanism Permanently Bypassed - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` returns `nil, nil` without writing any state. An authorized admin who sends `MsgTurnBridge{enable: false}` receives a success response, but the bridge is never actually disabled. All EVM-hook bridge paths (`SendToIbcHandler`, `SendToIbcV2Handler`, `SendCroToIbcHandler`) and the IBC conversion middleware continue to process transfers unconditionally, because no bridge-enabled flag is ever stored or checked.

### Finding Description

`TurnBridge` is the privileged message intended to halt the Gravity/IBC bridge in an emergency (per ADR-009). Its server implementation is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The handler writes nothing to the KV store and changes no parameter. The `Params` struct has no `EnableBridge` field: [2](#0-1) 

Every EVM-hook handler (`SendToIbcHandler.Handle`, `SendToIbcV2Handler`, `SendCroToIbcHandler`) calls `IbcTransferCoins` / `ibcSendTransfer` directly with no bridge-state guard: [3](#0-2) [4](#0-3) 

The IBC conversion middleware `OnRecvPacket` / `OnTimeoutPacket` / `OnAcknowledgementPacket` also perform token conversion with no bridge-state check: [5](#0-4) 

### Impact Explanation

**High — Bypass of Cronos admin/governance authority over the bridge.**

The bridge disable mechanism is the primary emergency stop for the Gravity/IBC bridge. Because `TurnBridge` is a no-op, any unprivileged user can continue to bridge tokens (CRC20/CRC21 → IBC, CRO → IBC, Gravity ERC20 → Cronos) even after the admin has explicitly attempted to halt the bridge. Token accounting, minting, and IBC escrow operations proceed without restriction, defeating the security control entirely.

### Likelihood Explanation

The `TurnBridge` proto surface is fully wired and reachable by any holder of `CanTurnBridge` permission. The admin sends the transaction, it succeeds, and the bridge silently continues. The bug is triggered every time the bridge-disable path is exercised. Any unprivileged user who continues to use the bridge after a "disable" event exploits the gap. [6](#0-5) 

### Recommendation

1. Add a `BridgeEnabled bool` field to `Params` (or a dedicated KV key).
2. In `TurnBridge`, write the new state: `k.SetBridgeEnabled(ctx, msg.Enable)`.
3. Add a guard at the top of every EVM-hook `Handle` method and in `IbcTransferCoins` / `ibcSendTransfer`:
   ```go
   if !k.GetBridgeEnabled(ctx) {
       return errors.New("bridge is disabled")
   }
   ```
4. Add the same guard in `IBCConversionModule.OnRecvPacket` for inbound conversion.

### Proof of Concept

1. Admin (holding `CanTurnBridge`) broadcasts `MsgTurnBridge{sender: admin, enable: false}`.
2. Chain returns `code: 0` — transaction accepted, no error.
3. Unprivileged user calls `crc21.send_to_ibc(recipient, amount)` on any mapped CRC21 contract.
4. `LogProcessEvmHook.PostTxProcessing` fires `SendToIbcHandler.Handle`.
5. `Handle` calls `IbcTransferCoins` → `ibcSendTransfer` → `transferKeeper.Transfer` — no bridge-state check anywhere in the call chain.
6. IBC packet is submitted and tokens leave Cronos, bypassing the admin's disable intent. [7](#0-6) [8](#0-7)

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
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

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L86-133)
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
```

**File:** x/cronos/keeper/ibc.go (L80-158)
```go
func (k Keeper) IbcTransferCoins(ctx sdk.Context, from, destination string, coins sdk.Coins, channelId string) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}

	if len(destination) == 0 {
		return errors.New("to address cannot be empty")
	}

	params := k.GetParams(ctx)
	evmParams := k.GetEvmParams(ctx)

	for _, c := range coins {
		switch c.Denom {
		case evmParams.EvmDenom:
			// Compute the remainder, we won't transfer anything lower than 10^10
			amount8decRem := c.Amount.Mod(sdkmath.NewIntFromBigInt(types.TenPowTen))
			amountToBurn := c.Amount.Sub(amount8decRem)
			if amountToBurn.IsZero() {
				// Amount too small
				continue
			}
			coins := sdk.NewCoins(sdk.NewCoin(evmParams.EvmDenom, amountToBurn))

			// Send evm tokens to escrow address
			err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, acc, types.ModuleName, coins)
			if err != nil {
				return err
			}
			// Burns the evm tokens
			if err := k.bankKeeper.BurnCoins(
				ctx, types.ModuleName, coins); err != nil {
				return err
			}

			// Transfer ibc tokens back to the user
			// We divide by 10^10 to come back to an 8decimals token
			amount8dec := c.Amount.Quo(sdkmath.NewIntFromBigInt(types.TenPowTen))
			ibcCoin := sdk.NewCoin(params.IbcCroDenom, amount8dec)
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, acc, sdk.NewCoins(ibcCoin),
			); err != nil {
				return err
			}

			// No need to specify the channelId because it's not a source token
			err = k.ibcSendTransfer(ctx, acc, destination, ibcCoin, "")
			if err != nil {
				return err
			}

		default:
			if !types.IsValidIBCDenom(c.Denom) && !types.IsValidCronosDenom(c.Denom) {
				return fmt.Errorf("the coin %s is neither an ibc voucher or a cronos token", c.Denom)
			}
			_, found := k.GetContractByDenom(ctx, c.Denom)
			if !found {
				return fmt.Errorf("coin %s is not supported", c.Denom)
			}
			err = k.ibcSendTransfer(ctx, acc, destination, c, channelId)
			if err != nil {
				return err
			}
		}
	}

	defer func() {
		for _, a := range coins {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "IbcTransferCoins"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()
	return nil
```

**File:** x/cronos/keeper/ibc.go (L161-194)
```go
func (k Keeper) ibcSendTransfer(ctx sdk.Context, sender sdk.AccAddress, destination string, coin sdk.Coin, channelId string) error {
	if types.IsSourceCoin(coin.Denom) {
		if !channeltypes.IsValidChannelID(channelId) {
			return errors.New("invalid channel id for ibc transfer of source token")
		}
	} else {
		// If it is not source, then coin is a voucher so we can extract the channel id from the denom
		channelDenom := coin.Denom
		sourceChannelID, err := k.GetSourceChannelID(ctx, channelDenom)
		if err != nil {
			return err
		}
		channelId = sourceChannelID
	}

	// Transfer coins to receiver through IBC
	// We use current time for timeout timestamp and zero height for timeoutHeight
	// it means it can never fail by timeout
	params := k.GetParams(ctx)
	timeoutTimestamp := uint64(ctx.BlockTime().UnixNano()) + params.IbcTimeout
	timeoutHeight := ibcclienttypes.ZeroHeight()
	msg := ibctransfertypes.MsgTransfer{
		SourcePort:       ibctransfertypes.PortID,
		SourceChannel:    channelId,
		Token:            coin,
		Sender:           sender.String(),
		Receiver:         destination,
		TimeoutHeight:    timeoutHeight,
		TimeoutTimestamp: timeoutTimestamp,
	}
	if _, err := k.transferKeeper.Transfer(ctx, &msg); err != nil {
		return err
	}
	return nil
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

**File:** x/cronos/keeper/permissions.go (L13-17)
```go
const (
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
)
```

**File:** x/cronos/keeper/evm_hooks.go (L28-44)
```go
func (h LogProcessEvmHook) PostTxProcessing(ctx sdk.Context, _ *core.Message, receipt *ethtypes.Receipt) error {
	addLogToReceiptFunc := newFuncAddLogToReceipt(receipt)
	for _, log := range receipt.Logs {
		if len(log.Topics) == 0 {
			continue
		}
		handler, ok := h.handlers[log.Topics[0]]
		if !ok {
			continue
		}
		err := handler.Handle(ctx, log.Address, log.Topics, log.Data, addLogToReceiptFunc)
		if err != nil {
			return err
		}
	}
	return nil
}
```
