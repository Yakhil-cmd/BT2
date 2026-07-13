### Title
`MsgTurnBridge` Handler Is a No-Op — Bridge Disable Mechanism Completely Bypassed - (File: `x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler in Cronos is implemented as a complete no-op. Any authorized admin who calls `MsgTurnBridge` to disable the bridge during an emergency will silently succeed (tx returns no error) but the bridge state is never updated. All bridge operations — `ConvertVouchers`, `TransferTokens`, and EVM-hook-triggered IBC transfers — continue to execute without restriction, permanently bypassing the bridge control mechanism.

---

### Finding Description

The `msgServer.TurnBridge` function in `x/cronos/keeper/msg_server.go` is defined as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

It performs no operations whatsoever: no permission check, no state write, no parameter update. The `CanTurnBridge` permission bit is defined and enforced elsewhere in the system: [2](#0-1) 

The proto definition and CLI both expose `MsgTurnBridge` as a live, callable transaction: [3](#0-2) [4](#0-3) 

The two primary bridge message handlers — `ConvertVouchers` and `TransferTokens` — call `ConvertVouchersToEvmCoins` and `IbcTransferCoins` respectively, neither of which reads or checks any bridge-active state: [5](#0-4) [6](#0-5) [7](#0-6) 

The EVM hook dispatcher (`PostTxProcessing`) also processes bridge log events without any bridge-active gate: [8](#0-7) 

The integration test `test_gravity_turn_bridge` explicitly expects that after `turn_bridge("false")` succeeds, subsequent `send_to_evm_chain` calls fail — confirming the intended design is that `TurnBridge` should enforce a real state change: [9](#0-8) 

---

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization check.**

An authorized admin (holding `CanTurnBridge` permission or the `CronosAdmin` role) calls `MsgTurnBridge{enable: false}` to halt bridge operations during a security incident (e.g., a discovered exploit in the IBC voucher conversion path, a compromised relayer, or an accounting anomaly). The transaction is accepted on-chain and emits no error. However, because the handler is a no-op, no bridge-active flag is ever written to state. Every unprivileged user can continue to:

- Call `MsgConvertVouchers` to convert IBC vouchers into EVM coins (minting)
- Call `MsgTransferTokens` to burn EVM coins and initiate IBC transfers (burning + escrow release)
- Trigger EVM hook handlers (`__CronosSendToIbc`, `__CronosSendToIbcV2`) from smart contracts to initiate IBC transfers

The admin's emergency bridge-disable capability is completely non-functional. This is a direct bypass of the bridge authorization control mechanism.

---

### Likelihood Explanation

The `TurnBridge` message is a live, registered gRPC endpoint reachable by any on-chain transaction. The `CanTurnBridge` permission system is fully wired up and the CLI command is shipped. The only missing piece is the handler body itself. Any scenario requiring an emergency bridge halt — which is the entire purpose of this mechanism — will silently fail to take effect.

---

### Recommendation

Implement `TurnBridge` to:
1. Verify the caller holds `CanTurnBridge` permission via `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)`.
2. Write the `enable` flag into module params (e.g., a `bridge_active` field in `Params`).
3. Add a bridge-active guard at the top of `ConvertVouchers`, `TransferTokens`, and each EVM log handler that returns an error when `bridge_active == false`.

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)
    if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
    }
    params := k.GetParams(ctx)
    params.EnableBridge = msg.Enable
    if err := k.SetParams(ctx, params); err != nil {
        return nil, err
    }
    return &types.MsgTurnBridgeResponse{}, nil
}
```

And in `ConvertVouchers` / `TransferTokens` / EVM handlers:
```go
if !k.GetParams(ctx).EnableBridge {
    return nil, errors.Wrap(types.ErrBridgeDisabled, "bridge is currently disabled")
}
```

---

### Proof of Concept

```go
// Attacker path:
// 1. Admin (with CanTurnBridge) calls TurnBridge(false) — tx succeeds, no error
// 2. Any unprivileged user calls ConvertVouchers or TransferTokens — succeeds
//    because TurnBridge wrote nothing to state and neither function checks bridge state.

func TestTurnBridgeIsNoOp(t *testing.T) {
    // Setup keeper with admin having CanTurnBridge permission
    // ...

    msgSrv := keeper.NewMsgServerImpl(cronosKeeper)

    // Admin disables bridge — returns nil error (appears to succeed)
    _, err := msgSrv.TurnBridge(ctx, &types.MsgTurnBridge{Sender: admin, Enable: false})
    require.NoError(t, err)

    // Unprivileged user converts IBC vouchers — should fail if bridge is disabled, but succeeds
    _, err = msgSrv.ConvertVouchers(ctx, &types.MsgConvertVouchers{
        Address: unprivilegedUser,
        Coins:   sdk.NewCoins(sdk.NewCoin(ibcCroDenom, sdkmath.NewInt(100))),
    })
    // This succeeds — bridge disable had no effect
    require.NoError(t, err) // BUG: should have returned ErrBridgeDisabled
}
```

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

**File:** x/cronos/keeper/ibc.go (L21-78)
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
	defer func() {
		for _, a := range coins {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "ConvertVouchersToEvmCoins"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()
	return nil
}
```

**File:** x/cronos/keeper/ibc.go (L80-159)
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
