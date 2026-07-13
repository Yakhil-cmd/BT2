### Title
`TurnBridge` Is a Permanent No-Op, Bypassing Admin Emergency Bridge-Disable Authorization — (`x/cronos/keeper/msg_server.go`)

### Summary
The `TurnBridge` message handler is implemented as an unconditional stub that returns `(nil, nil)` without performing any state change. No bridge-enabled flag is ever written, and no bridge operation in the EVM-hook or IBC-conversion paths checks such a flag. The admin's emergency bridge-disable authority is therefore permanently and silently bypassed: any unprivileged user can continue to bridge assets after the admin has submitted a `MsgTurnBridge` to halt the bridge.

### Finding Description
`msg_server.go` line 85–87 implements `TurnBridge` as a stub:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

Contrast this with the correctly-guarded `UpdateTokenMapping`, which enforces a permission check before acting:

```go
if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
    return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
}
``` [2](#0-1) 

`TurnBridge` has neither a permission check nor any implementation. Because no bridge-enabled state is ever written, every downstream bridge path is unconditionally open:

- **EVM-hook path** (`SendToIbcHandler.handle`, `SendToIbcV2Handler.Handle`, `SendCroToIbcHandler.Handle`): none of these handlers check a bridge-enabled flag before minting/sending coins and initiating IBC transfers. [3](#0-2) [4](#0-3) 

- **IBC-conversion middleware** (`IBCConversionModule.OnRecvPacket`): the only gate is `canBeConverted`, which checks only for a contract mapping — not whether the bridge is enabled. [5](#0-4) 

- **Cosmos message path** (`MsgTransferTokens` → `IbcTransferCoins`): no bridge-enabled check before initiating the IBC transfer. [6](#0-5) 

ADR-009 explicitly names "disabling the bridge module in case of emergency" as a core use-case for the permission system and lists `MsgTurnBridge` as a restricted message. The stub implementation makes that control permanently inoperative.

### Impact Explanation
**High — Bypass of Cronos admin bridge authorization checks.**

If a critical vulnerability is discovered in any bridge path (e.g., an accounting error in `IbcTransferCoins`, a reentrancy in an EVM hook, or a supply-inflation bug in `ConvertVouchersToEvmCoins`), the admin has no on-chain mechanism to halt the bridge. Unprivileged users can continue to drain or corrupt bridge-controlled assets indefinitely, because the intended emergency circuit-breaker is silently discarded.

### Likelihood Explanation
Certainty. `TurnBridge` is always a no-op; the bypass is unconditional and requires no special conditions or attacker setup. Any user who submits a bridge transaction after the admin has called `MsgTurnBridge` exploits this gap.

### Recommendation
1. Add a `bridge_enabled bool` (or equivalent) field to the cronos module `Params`.
2. Implement `TurnBridge` to write that flag and enforce the `CanTurnBridge` permission (mirroring the pattern in `UpdateTokenMapping`).
3. Add a guard at the top of every bridge entry point (`SendToIbcHandler.handle`, `SendToIbcV2Handler.Handle`, `SendCroToIbcHandler.Handle`, `IbcTransferCoins`, and `IBCConversionModule.OnRecvPacket`) that returns an error when `bridge_enabled == false`.

### Proof of Concept
1. A critical accounting bug is found in `IbcTransferCoins`.
2. The Cronos admin submits `MsgTurnBridge{Enabled: false}` to halt the bridge.
3. `TurnBridge` executes, returns `(nil, nil)`, writes nothing to state — tx succeeds with no effect.
4. An unprivileged user calls `send_to_ibc` on any CRC21 contract; the EVM hook fires `SendToIbcHandler.Handle`, which calls `IbcTransferCoins` with no bridge-enabled gate.
5. The bridge continues to operate, and the accounting bug remains exploitable.

### Citations

**File:** x/cronos/keeper/msg_server.go (L47-65)
```go
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

**File:** x/cronos/keeper/msg_server.go (L73-75)
```go
	if !k.HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping) {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
```

**File:** x/cronos/keeper/msg_server.go (L85-87)
```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
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

**File:** x/cronos/keeper/evmhandlers/send_cro_to_ibc.go (L68-103)
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
```

**File:** x/cronos/middleware/conversion_middleware.go (L256-263)
```go
func (im IBCConversionModule) canBeConverted(ctx sdk.Context, denom string) bool {
	params := im.cronoskeeper.GetParams(ctx)
	if denom == params.IbcCroDenom {
		return true
	}
	_, found := im.cronoskeeper.GetContractByDenom(ctx, denom)
	return found
}
```
