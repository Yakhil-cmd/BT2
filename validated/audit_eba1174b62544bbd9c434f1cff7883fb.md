### Title
`TurnBridge` Handler Is a No-Op Stub — Bridge Cannot Be Disabled by Admin - (File: x/cronos/keeper/msg_server.go)

### Summary

The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is an unimplemented stub that unconditionally returns `nil, nil` without performing any state change. An authorized admin calling `MsgTurnBridge` to disable the bridge will receive a success response, but the bridge is never actually disabled. Cross-chain bridge flows (`__CronosSendToIbc`, `__CronosSendToEvmChain`) continue to execute unimpeded, permanently bypassing the admin's emergency bridge-shutdown authority.

### Finding Description

`TurnBridge` in `msg_server.go` is defined as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

The handler performs no state mutation — it never reads `msg.Enable`, never calls `k.SetParams`, and never writes a `bridge_active` flag to the KV store. The transaction is accepted and returns success, but the intended effect (toggling the bridge off) never occurs.

The EVM hook dispatcher `PostTxProcessing` iterates over all receipt logs and dispatches to registered handlers without any bridge-active guard:

```go
func (h LogProcessEvmHook) PostTxProcessing(ctx sdk.Context, _ *core.Message, receipt *ethtypes.Receipt) error {
    for _, log := range receipt.Logs {
        ...
        err := handler.Handle(ctx, log.Address, log.Topics, log.Data, addLogToReceiptFunc)
        ...
    }
    return nil
}
``` [2](#0-1) 

Similarly, `IbcTransferCoins` in `ibc.go` performs no check against a `bridge_active` parameter before initiating IBC sends: [3](#0-2) 

ADR-001 explicitly documents that `bridge_active` is the intended governance parameter for disabling the bridge in emergencies:

> "the logic of the gravity module can be controlled through the governance parameter `bridge_active` which still leave us the option to disable it if necessary." [4](#0-3) 

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization.**

When a security incident is discovered (e.g., a bug in the IBC transfer path, a compromised token mapping, or a LayerZero/IBC library vulnerability), the designated admin is expected to call `TurnBridge(false)` to halt all outgoing bridge activity. Because the handler is a stub, this call silently succeeds but leaves the bridge fully operational. Any user can continue to call `send_to_ibc` or `send_to_evm_chain` on any CRC20/CRC21 contract, and the EVM hooks will faithfully execute the cross-chain transfer. The emergency shutdown mechanism is completely non-functional, matching the "Bypass of Cronos admin… bridge… authorization checks" High impact category.

### Likelihood Explanation

The `TurnBridge` CLI command and proto message are fully wired and exposed to authorized callers. An admin who believes they have disabled the bridge has no on-chain signal that the operation was a no-op. Any subsequent bridge activity will appear to be a protocol failure rather than a code defect, making this easy to miss during an incident response.

### Recommendation

Implement `TurnBridge` to write the `enable` flag into the module params:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    // permission check (e.g. HasPermission or CronosAdmin)
    params := k.GetParams(ctx)
    params.EnableAutoDeployment = msg.Enable  // or a dedicated bridge_active field
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

Add a `bridge_active` guard at the top of `PostTxProcessing` (or inside each relevant `EvmLogHandler.Handle`) and at the entry of `IbcTransferCoins`, returning an error when the bridge is disabled.

### Proof of Concept

1. Admin holds the `CanTurnBridge` permission.
2. Admin submits `MsgTurnBridge{Enable: false}`.
3. Transaction is accepted; `TurnBridge` returns `nil, nil` — no state written.
4. User calls `send_to_ibc(recipient, amount, channelId, extraData)` on a CRC20/CRC21 contract.
5. EVM emits `__CronosSendToIbc`; `PostTxProcessing` dispatches to the IBC send handler.
6. `IbcTransferCoins` executes the IBC transfer — bridge is still live despite the admin's shutdown attempt.
7. The admin has no way to halt bridge activity short of a governance upgrade.

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
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

**File:** x/cronos/keeper/ibc.go (L80-145)
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
```

**File:** docs/architecture/adr-001.md (L42-42)
```markdown
The unsafe-experimental flag will be removed from the code base as the module is stable enough to be added to cronos. Moreover, the logic of the gravity module can be controlled through the governance parameter "bridge_active" which still leave us the option to disable it if necessary.
```
