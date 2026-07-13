### Title
`TurnBridge` Emergency-Stop Is a No-Op — Bridge Minting/Conversion Cannot Be Halted During a Security Incident - (File: `x/cronos/keeper/msg_server.go`)

### Summary

The `TurnBridge` message handler, which is the designated mechanism for disabling the Cronos bridge during a security incident, is implemented as a complete no-op. It stores no state and performs no action. As a result, the bridge-disable emergency control is permanently bypassed: any unprivileged user can continue to trigger minting and token conversion operations even after an authorized admin has called `TurnBridge(false)`.

### Finding Description

The `TurnBridge` gRPC handler in `x/cronos/keeper/msg_server.go` is:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

It returns `nil, nil` — success — without reading `msg.Enable`, writing any state, or performing any action. The `Params` struct has no `bridge_enabled` field: [2](#0-1) 

Because no bridge-enabled flag is ever stored, none of the minting and conversion paths can check it. Specifically:

1. **`ConvertVouchersToEvmCoins`** — mints `basetcro` EVM tokens from IBC-CRO and calls `ConvertCoinFromNativeToCRC21` for other IBC denoms, with no bridge-enabled guard: [3](#0-2) 

2. **`ConvertCoinFromNativeToCRC21`** — calls `mint_by_cronos_module` on the CRC21 contract, with no bridge-enabled guard: [4](#0-3) 

3. **`IBCConversionModule.OnRecvPacket`** — auto-converts IBC vouchers to EVM coins on every inbound IBC packet, with no bridge-enabled guard: [5](#0-4) 

4. **`BankContract.Run` (mint method)** — the bank precompile mint path also has no bridge-enabled guard: [6](#0-5) 

5. **`MsgConvertVouchers` handler** — directly calls `ConvertVouchersToEvmCoins` with no bridge-enabled check: [7](#0-6) 

The `TurnBridge` message is proto-defined and CLI-exposed as a real security control: [8](#0-7) 

The integration test `test_gravity_turn_bridge` explicitly validates that after `turn_bridge("false")`, bridge operations should fail — confirming this is the intended emergency-stop mechanism, not a placeholder: [9](#0-8) 

### Impact Explanation

**High — Bypass of Cronos bridge authorization checks.**

When a security incident occurs (e.g., a bridge vulnerability is being exploited), the authorized admin calls `TurnBridge(false)`. The transaction is accepted on-chain and returns success, giving the false impression that the bridge is disabled. In reality, nothing changes: all minting and conversion paths (`MsgConvertVouchers`, IBC `OnRecvPacket` auto-conversion, `BankContract` precompile mint, `ConvertCoinFromNativeToCRC21`) continue to execute without restriction. An attacker can continue to mint CRC20/CRC21 tokens or convert IBC vouchers to EVM coins indefinitely, draining the bridge escrow or inflating token supply, while the admin believes the bridge is off.

### Likelihood Explanation

The `TurnBridge` no-op is reachable by any user who submits a `MsgConvertVouchers` transaction or triggers an IBC transfer that auto-converts. No special privileges are required to exploit the continued minting — the admin's failed disable attempt is the only precondition, and that precondition is met any time an admin responds to a security incident. The `CanTurnBridge` permission system exists and is enforced at the message level, confirming the feature was intended to be functional. [10](#0-9) 

### Recommendation

1. Add a `bridge_enabled bool` field to `Params` (or a dedicated KV store key).
2. Implement `TurnBridge` to write that flag: check `HasPermission(ctx, signers, CanTurnBridge)`, then persist `msg.Enable`.
3. Add a `requireBridgeEnabled` guard (or equivalent check) at the top of `ConvertVouchersToEvmCoins`, `ConvertCoinFromNativeToCRC21`, and `IBCConversionModule.OnRecvPacket` that returns an error when the bridge is disabled.
4. Optionally gate the `BankContract` precompile mint path on the same flag.

### Proof of Concept

1. Admin holds `CanTurnBridge` permission.
2. A bridge vulnerability is discovered; admin broadcasts `MsgTurnBridge{Sender: admin, Enable: false}`.
3. Transaction succeeds on-chain (`return nil, nil`), no state is written.
4. Attacker broadcasts `MsgConvertVouchers{Address: attacker, Coins: [large IBC voucher amount]}`.
5. `ConvertVouchersToEvmCoins` executes: IBC vouchers are escrowed, `basetcro` EVM tokens are minted and sent to the attacker — no bridge-enabled check is reached.
6. Attacker repeats indefinitely; admin's `TurnBridge(false)` call had zero effect.

### Citations

**File:** x/cronos/keeper/msg_server.go (L27-44)
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
```

**File:** x/cronos/keeper/msg_server.go (L84-87)
```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
	return nil, nil
}
```

**File:** proto/cronos/cronos.proto (L9-19)
```text
message Params {
  option (gogoproto.goproto_stringer) = false;
  string ibc_cro_denom                = 1 [(gogoproto.moretags) = "yaml:\"ibc_cro_denom,omitempty\""];
  uint64 ibc_timeout                  = 2;
  // the admin address who can update token mapping
  string cronos_admin           = 3;
  bool   enable_auto_deployment = 4;
  uint64 max_callback_gas       = 5;
  // the authorized contract addresses for the SendCroToIbc hook; empty list disables the hook
  repeated string cro_bridge_contract_addresses = 6;
}
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

**File:** x/cronos/keeper/evm.go (L91-143)
```go
func (k Keeper) ConvertCoinFromNativeToCRC21(ctx sdk.Context, sender common.Address, coin sdk.Coin, autoDeploy bool) error {
	if !types.IsValidCoinDenom(coin.Denom) {
		return fmt.Errorf("coin %s is not supported for conversion", coin.Denom)
	}
	var err error
	// external contract is returned in preference to auto-deployed ones
	contract, found := k.GetContractByDenom(ctx, coin.Denom)
	if !found {
		if !autoDeploy {
			return fmt.Errorf("no contract found for the denom %s", coin.Denom)
		}
		contract, err = k.DeployModuleCRC21(ctx, coin.Denom)
		if err != nil {
			return err
		}
		if err = k.SetAutoContractForDenom(ctx, coin.Denom, contract); err != nil {
			return err
		}

		k.Logger(ctx).Info(fmt.Sprintf("contract address %s created for coin denom %s", contract.String(), coin.Denom))
	}

	isSource := types.IsSourceCoin(coin.Denom)
	coins := sdk.NewCoins(coin)
	if isSource {
		// burn coins
		err = k.bankKeeper.SendCoinsFromAccountToModule(ctx, sdk.AccAddress(sender.Bytes()), types.ModuleName, sdk.NewCoins(coin))
		if err != nil {
			return err
		}
		err = k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins)
		if err != nil {
			return err
		}
		// unlock crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "transfer_from_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
	} else {
		// send coins to contract address
		err = k.bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)
		if err != nil {
			return err
		}
		// mint crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
	}

	return nil
```

**File:** x/cronos/middleware/conversion_middleware.go (L106-147)
```go
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

**File:** x/cronos/keeper/precompiles/bank.go (L132-142)
```go
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if method.Name == "mint" {
				if err := bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to mint coins in precompiled contract")
				}
				if err := bc.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send mint coins to account")
				}
```

**File:** proto/cronos/tx.proto (L29-30)
```text
  // TurnBridge defines a method to disable or enable the gravity bridge
  rpc TurnBridge(MsgTurnBridge) returns (MsgTurnBridgeResponse);
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

**File:** x/cronos/keeper/permissions.go (L14-16)
```go
	CanChangeTokenMapping uint64                                  = 1 << iota // 1
	CanTurnBridge                                                             // 2
	All                   = CanChangeTokenMapping | CanTurnBridge             // 3
```
