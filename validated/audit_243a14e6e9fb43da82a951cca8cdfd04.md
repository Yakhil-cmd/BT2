### Title
`MsgTurnBridge` Handler is a No-Op — `CanTurnBridge` Permission Bypassed and Bridge State Never Stored, Preventing Emergency Bridge Disablement - (File: x/cronos/keeper/msg_server.go)

### Summary
The `TurnBridge` message handler in `x/cronos/keeper/msg_server.go` is a complete no-op: it performs no permission check and stores no state. Any unprivileged user can call it successfully, and the bridge-enabled/disabled state is never written. As a result, the EVM bridge handlers (`SendToIbcHandler`, `SendToIbcV2Handler`, `SendCroToIbcHandler`) always process bridge operations regardless of any intended disabled state, because there is no state to check.

### Finding Description

The `TurnBridge` message handler is implemented as:

```go
// TurnBridge implements the grpc method
func (k msgServer) TurnBridge(goCtx context.Context, msg *types.MsgTurnBridge) (*types.MsgTurnBridgeResponse, error) {
    return nil, nil
}
``` [1](#0-0) 

It does two things wrong simultaneously:

1. **No permission check**: `UpdateTokenMapping` correctly gates on `HasPermission(ctx, msg.GetSigners(), CanChangeTokenMapping)`. `TurnBridge` performs no equivalent check for `CanTurnBridge`, which is a defined permission value (`2`) in the permission system. [2](#0-1) 

2. **No state write**: The handler never stores a bridge-enabled/disabled flag anywhere in the KV store. The `MsgTurnBridge` proto message carries a `bool enable` field, but it is silently discarded. [3](#0-2) 

Because no state is ever written, the EVM log handlers that process outbound bridge operations — `SendToIbcHandler.handle`, `SendToIbcV2Handler.Handle`, and `SendCroToIbcHandler.Handle` — have no bridge-enabled flag to consult. They proceed unconditionally: [4](#0-3) [5](#0-4) 

The `CanTurnBridge` permission is advertised in the CLI help text (`"permission value: 1=CanChangeTokenMapping, 2:=CanTurnBridge, 3=All"`) and is a named constant in the permission system, but it is never enforced at the message-server boundary. [6](#0-5) 

### Impact Explanation

Two distinct High-severity impacts arise:

**1. Bypass of `CanTurnBridge` authorization (High — auth bypass):** Any unprivileged user can submit `MsgTurnBridge` and receive a success response. The `CanTurnBridge` permission is never checked, so the entire permission-gating mechanism for bridge control is bypassed. This directly matches the allowed impact: *"Bypass of Cronos admin, governance authority, permission… authorization checks."*

**2. Bridge can never be disabled (High — permanent inability to exercise emergency controls):** Because no state is stored, even a legitimately authorized admin cannot disable the bridge. The EVM handlers for `__CronosSendToIbc` and `__CronosSendToEvmChain` events will always execute bridge transfers. In an emergency (e.g., a critical bug in a CRC20/CRC21 contract, a compromised IBC channel, or an exploit in progress), the bridge cannot be halted. This matches: *"Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows… under normal network assumptions"* — specifically the inability of the authorized party to stop flows.

### Likelihood Explanation

The no-op handler is unconditionally reachable by any account that can submit a Cosmos SDK transaction. No special privilege, leaked key, or cryptographic break is required. The `MsgTurnBridge` message is a standard proto-defined tx surface exposed via gRPC and the CLI (`cronosd tx cronos turn-bridge`). The likelihood is high because the code path is trivially reachable and the defect is structural (the entire handler body is missing).

### Recommendation

1. **Enforce the permission check** at the top of `TurnBridge`, mirroring `UpdateTokenMapping`:
   ```go
   if !k.HasPermission(ctx, msg.GetSigners(), CanTurnBridge) {
       return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
   }
   ```

2. **Store the bridge-enabled state** in the KV store (e.g., under a `KeyPrefixBridgeEnabled` key) and read it back in `SendToIbcHandler.handle`, `SendToIbcV2Handler.Handle`, and `SendCroToIbcHandler.Handle` before processing any bridge operation, returning an error if the bridge is disabled.

### Proof of Concept

1. Any account (e.g., `signer1` with no special permissions) submits:
   ```
   cronosd tx cronos turn-bridge false --from signer1
   ```
2. The transaction is accepted on-chain with code `0` (success), because `TurnBridge` returns `nil, nil` unconditionally. [1](#0-0) 
3. No bridge-disabled state is written anywhere.
4. A CRC21 contract user calls `send_to_ibc(recipient, amount, channel_id, extraData)`, emitting `__CronosSendToIbc`. [7](#0-6) 
5. `SendToIbcV2Handler.Handle` processes the log and calls `IbcTransferCoins` without consulting any bridge-enabled flag, completing the transfer as if the bridge were never disabled. [8](#0-7) 
6. The bridge is permanently un-disableable; the authorized admin has no recourse.

### Citations

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

**File:** proto/cronos/tx.proto (L82-89)
```text
message MsgTurnBridge {
  option (cosmos.msg.v1.signer) = "sender";
  string sender                 = 1;
  bool   enable                 = 2;
}

// MsgTurnBridgeResponse defines the response type
message MsgTurnBridgeResponse {}
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

**File:** x/cronos/client/cli/tx.go (L292-319)
```go
// CmdUpdatePermissions returns a CLI command handler for updating cronos permissions
func CmdUpdatePermissions() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-permissions [address] [permissions]",
		Short: "Update Permissions, permission value: 1=CanChangeTokenMapping, 2:=CanTurnBridge, 3=All",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			argsAddress := args[0]
			argPermissions, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return err
			}
			msg := types.NewMsgUpdatePermissions(clientCtx.GetFromAddress().String(), argsAddress, argPermissions)
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

**File:** contracts/src/ModuleCRC21.sol (L60-67)
```text
    function send_to_ibc(string memory recipient, uint amount, uint channel_id, bytes memory extraData) public {
        if (isSource) {
            transferFrom(msg.sender, module_address, amount);
        } else {
            unsafe_burn(msg.sender, amount);
        }
        emit __CronosSendToIbc(msg.sender, channel_id, recipient, amount, extraData);
    }
```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc_v2.go (L70-101)
```go
func (h SendToIbcV2Handler) Handle(
	ctx sdk.Context,
	contract common.Address,
	topics []common.Hash,
	data []byte,
	_ func(contractAddress common.Address, logSig common.Hash, logData []byte),
) error {
	if len(topics) != 3 {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Info("log signature matches but wrong number of indexed events")
		for i, topic := range topics {
			h.cronosKeeper.Logger(ctx).Debug(fmt.Sprintf("topic index: %d value: %s", i, topic.TerminalString()))
		}
		return nil
	}

	unpacked, err := SendToIbcEventV2.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Error("log signature matches but failed to decode", "error", err)
		return nil
	}

	// needs to crope the extra bytes in the topic by using BytesToAddress
	sender := common.BytesToAddress(topics[1].Bytes())
	channelId := new(big.Int).SetBytes(topics[2].Bytes())
	recipient := unpacked[0].(string)
	amount := unpacked[1].(*big.Int)
	// extraData := unpacked[2].([]byte)

	return h.handle(ctx, contract, sender, recipient, amount, channelId)
}
```
