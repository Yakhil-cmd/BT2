### Title
`MsgTurnBridge` Is a No-Op Stub — Bridge Cannot Be Disabled by Admin - (File: `x/cronos/keeper/msg_server.go`)

---

### Summary

The `TurnBridge` message handler, which is the designated emergency circuit-breaker for the Gravity bridge, is implemented as a complete no-op (`return nil, nil`). It neither enforces the `CanTurnBridge` permission check nor writes any bridge-enabled/disabled state. As a result, the admin's ability to disable the bridge is permanently bypassed: any call to `MsgTurnBridge(enable=false)` silently succeeds while the bridge continues operating normally.

---

### Finding Description

`MsgTurnBridge` is a fully-defined, permissioned message in the Cronos module. The permission system (`CanTurnBridge`) and the CLI command (`CmdTurnBridge`) are both wired up and functional. However, the server-side handler in `x/cronos/keeper/msg_server.go` is:

```go
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

This stub:

1. **Does not check `CanTurnBridge` permission** — any unprivileged address can call it and receive a success response.
2. **Does not write any bridge-enabled/disabled flag** — no such field exists in `Params` and no KV store key is written.
3. **Has no downstream effect** — the EVM log handlers (`SendToIbcHandler`, `SendCroToIbcHandler`, `SendToIbcV2Handler`) registered in `app.go` have no bridge-state gate to check. [2](#0-1) 

The `Params` struct confirms there is no `bridge_enabled` boolean: [3](#0-2) 

The `SendToIbcHandler.handle` function proceeds directly to `IbcTransferCoins` with no bridge-state check: [4](#0-3) 

The `SendCroToIbcHandler` only checks `CroBridgeContractAddresses` (a separate allowlist), not any bridge-enabled flag: [5](#0-4) 

The integration test `test_gravity_turn_bridge` demonstrates the intended behavior — after `turn_bridge("false")`, bridge operations are expected to fail — but this expectation is never satisfied because the handler is a stub: [6](#0-5) 

---

### Impact Explanation

**High — Bypass of Cronos admin bridge authorization check.**

The `TurnBridge` mechanism is the emergency circuit-breaker for the Gravity bridge. If a bridge exploit or draining attack is detected, the admin (or a permissioned address) is expected to call `MsgTurnBridge(enable=false)` to halt outbound transfers. Because the handler is a no-op, this halt never takes effect. Bridge-triggered EVM log handlers continue to process `__CronosSendToIbc` and `__CronosSendCroToIbc` events, allowing tokens (IBC vouchers, CRC20/CRC21 assets, CRO) to continue flowing out of Cronos to Ethereum or other IBC chains. The admin's authorization to stop the bridge is completely bypassed.

---

### Likelihood Explanation

Certain. The stub is unconditional — every call to `MsgTurnBridge` returns success without side effects. No special conditions are required to trigger the bypass; it is the default behavior of the handler.

---

### Recommendation

Implement `TurnBridge` to:

1. Verify the sender holds `CanTurnBridge` permission via `k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge)`.
2. Persist the bridge-enabled flag (add a `bridge_enabled` field to `Params` or a dedicated KV key).
3. Add a guard at the top of `SendToIbcHandler.handle`, `SendCroToIbcHandler.Handle`, and `SendToIbcV2Handler.Handle` that reads the flag and returns an error when the bridge is disabled.

---

### Proof of Concept

1. Admin holds `CanTurnBridge` permission and calls `MsgTurnBridge{Sender: admin, Enable: false}`.
2. The handler returns `nil, nil` — the call is recorded on-chain as successful.
3. An unprivileged user deploys or calls a CRC20 contract that emits `__CronosSendToIbc(sender, recipient, amount)`.
4. `LogProcessEvmHook.PostTxProcessing` dispatches to `SendToIbcHandler.Handle`.
5. `SendToIbcHandler.handle` finds no bridge-state check, calls `IbcTransferCoins`, and the IBC transfer is initiated.
6. Tokens leave Cronos despite the admin having "disabled" the bridge. [7](#0-6)

### Citations

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** app/app.go (L851-856)
```go
	app.EvmKeeper.SetHooks(cronoskeeper.NewLogProcessEvmHook(
		evmhandlers.NewSendToAccountHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendCroToIbcHandler(app.BankKeeper, app.CronosKeeper),
		evmhandlers.NewSendToIbcV2Handler(app.BankKeeper, app.CronosKeeper),
	))
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

**File:** x/cronos/keeper/evmhandlers/send_cro_to_ibc.go (L75-80)
```go
	authorizedBridges := h.cronosKeeper.GetParams(ctx).CroBridgeContractAddresses
	if !slices.ContainsFunc(authorizedBridges, func(addr string) bool {
		return common.HexToAddress(addr) == contract
	}) {
		return fmt.Errorf("contract %s is not authorized to use SendCroToIbc hook", contract)
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
