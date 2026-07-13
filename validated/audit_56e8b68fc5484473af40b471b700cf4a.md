### Title
Fee-on-Transfer Token Accounting Mismatch in `ModuleCRC20Proxy.send_to_ibc()` Causes Native Source Coin Over-Minting - (`contracts/src/ModuleCRC20Proxy.sol`)

---

### Summary

When a `ModuleCRC20Proxy` wraps a fee-on-transfer ERC20 with `isSource = true`, calling `send_to_ibc()` emits `__CronosSendToIbc` with the full requested `amount`, but the proxy only receives `amount - fee` of the underlying ERC20. The `SendToIbcHandler` then mints `amount` native source coins from the event log, creating a persistent accounting deficit: more native coins are minted than the underlying ERC20 held by the proxy.

---

### Finding Description

**Step 1 — Contract emits inflated amount.**

In `ModuleCRC20Proxy.send_to_ibc()` for `isSource = true`:

```solidity
function send_to_ibc(string memory recipient, uint amount, uint channel_id, bytes memory extraData) public {
    if (isSource) {
        crc20Contract.move(msg.sender, address(this), amount);  // proxy receives amount - fee
    } else {
        crc20_burn(msg.sender, amount);
    }
    emit __CronosSendToIbc(msg.sender, channel_id, recipient, amount, extraData);  // emits full amount
}
```

If `crc20Contract` is a fee-on-transfer ERC20, `crc20Contract.move()` (equivalent to `transferFrom`) delivers `amount - fee` to the proxy, but the event records `amount`. [1](#0-0) 

**Step 2 — Handler mints based on event log, not actual balance.**

`SendToIbcHandler.handle()` reads `amount` from the event and for source coins unconditionally mints that full amount as native coins:

```go
amount := sdkmath.NewIntFromBigInt(amountInt)
coins := sdk.NewCoins(sdk.NewCoin(denom, amount))

if types.IsSourceCoin(denom) {
    if err = h.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil { ... }
    if err = h.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sender, coins); err != nil { ... }
}
// Initiate IBC transfer from sender account
if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins, channelId); err != nil { ... }
```

There is no balance-before/after check on the proxy contract. The handler trusts the event-logged `amount` entirely. [2](#0-1) 

**Step 3 — Insolvency on redemption.**

When native source coins return to Cronos and a user calls `ConvertCoinFromNativeToCRC21`, the keeper calls `transfer_from_cronos_module(sender, amount)` on the proxy:

```solidity
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    crc20Contract.transfer(addr, amount);  // proxy may not hold enough
}
```

The proxy holds only `amount - fee` per round-trip, but must satisfy `amount` per redemption. [3](#0-2) 

The same mismatch exists in `send_to_evm_chain()` for the `isSource = true` path. [4](#0-3) 

---

### Impact Explanation

**Critical — Unauthorized balance/accounting change for CRC20/ERC20 assets.**

Each `send_to_ibc()` call mints `amount` native source coins while the proxy accumulates only `amount - fee` underlying ERC20. The deficit grows linearly with usage. When users convert native coins back to the underlying ERC20, the proxy cannot satisfy all redemptions. The last redeemers lose funds equal to the accumulated transfer fees. This is a direct, permanent accounting corruption of the CRC20/native token supply backed by the proxy.

---

### Likelihood Explanation

The `ModuleCRC20Proxy` is a production contract in `contracts/src/` designed to wrap arbitrary external ERC20 tokens. Registering a token mapping requires admin permission (`CanChangeTokenMapping`), but this is a routine administrative action — not a compromise. An admin who registers a fee-on-transfer ERC20 (e.g., a token that later enables fees, or one whose fee mechanism is not immediately obvious) will unknowingly trigger this bug. The protocol performs no validation that the wrapped ERC20 is non-fee-on-transfer at registration time. [5](#0-4) 

---

### Recommendation

1. **Balance-before/after check in `ModuleCRC20Proxy.send_to_ibc()`**: Record the proxy's balance of `crc20Contract` before and after the `move()` call, and emit the actual received amount in the event rather than the user-supplied `amount`.

2. **Validation at registration**: In `RegisterOrUpdateTokenMapping`, call the candidate contract to verify that a round-trip transfer does not lose value (i.e., reject fee-on-transfer tokens for source mappings).

3. **Handler-side verification**: In `SendToIbcHandler.handle()` for source coins, query the proxy's actual underlying balance change rather than trusting the event-logged amount.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 with a 2% transfer fee.
2. Deploy `ModuleCRC20Proxy` wrapping it with `isSource = true`.
3. Admin calls `MsgUpdateTokenMapping` to register the proxy (routine admin action).
4. User calls `proxy.send_to_ibc(recipient, 1000, channel_id, b"")`.
   - Proxy receives **980** underlying ERC20 (after 2% fee).
   - Event emits `amount = 1000`.
5. `SendToIbcHandler` mints **1000** native source coins and initiates IBC transfer.
6. IBC transfer completes; user receives 1000 native coins on the destination chain.
7. User bridges back: 1000 native coins arrive on Cronos.
8. User calls `ConvertCoinFromNativeToCRC21` with 1000 native coins.
   - Keeper burns 1000 native coins.
   - Calls `proxy.transfer_from_cronos_module(user, 1000)`.
   - Proxy attempts `crc20Contract.transfer(user, 1000)` but only holds **980**.
   - Transfer fails (or drains other depositors' funds if the proxy has accumulated deposits from others).
9. Net result: **20 underlying ERC20 permanently unaccounted for** per 1000-unit round-trip. With N users, the last redeemer cannot recover their full deposit.

### Citations

**File:** contracts/src/ModuleCRC20Proxy.sol (L56-59)
```text
    function transfer_from_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        crc20Contract.move(address(this), addr, amount);
    }
```

**File:** contracts/src/ModuleCRC20Proxy.sol (L67-75)
```text
    function send_to_evm_chain(address recipient, uint amount, uint chain_id, uint bridge_fee, bytes calldata extraData) external {
        // transfer back the token to the proxy account
        if (isSource) {
            crc20Contract.move(msg.sender, address(this), add(amount, bridge_fee));
        } else {
            crc20_burn(msg.sender, add(amount, bridge_fee));
        }
        emit __CronosSendToEvmChain(msg.sender, recipient, chain_id, amount, bridge_fee, extraData);
    }
```

**File:** contracts/src/ModuleCRC20Proxy.sol (L78-85)
```text
    function send_to_ibc(string memory recipient, uint amount, uint channel_id, bytes memory extraData) public {
        if (isSource) {
            crc20Contract.move(msg.sender, address(this), amount);
        } else {
            crc20_burn(msg.sender, amount);
        }
        emit __CronosSendToIbc(msg.sender, channel_id, recipient, amount, extraData);
    }
```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L105-130)
```go
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
```

**File:** x/cronos/keeper/msg_server.go (L68-81)
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
```
