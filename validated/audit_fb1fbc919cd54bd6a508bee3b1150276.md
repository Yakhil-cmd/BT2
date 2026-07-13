### Title
Missing Contract-Existence Check at Conversion Time Enables Permanent Loss of IBC Vouchers and Source Coins via Dead-Contract Mapping — (File: `x/cronos/keeper/evm.go`)

---

### Summary

`ConvertCoinFromNativeToCRC21` performs irreversible bank operations (burning source coins or sending IBC tokens to a contract address) **before** calling the mapped CRC21 contract. The contract-existence guard (`ensureContractCode`) is enforced only at registration time in `RegisterOrUpdateTokenMapping`, never at conversion time. If the mapped contract is destroyed after registration (e.g., via `selfdestruct`), `CallModuleCRC21` silently succeeds — EVM calls to a codeless address return success with empty data — and the irreversible bank operations are committed without the corresponding CRC21 token operations completing.

---

### Finding Description

`ensureContractCode` is called inside `RegisterOrUpdateTokenMapping` at lines 341 and 394: [1](#0-0) 

It is **not** called anywhere in the conversion path: `ConvertCoinFromNativeToCRC21` → `ConvertVouchersToEvmCoins` → `OnRecvVouchers` / IBC middleware.

In `ConvertCoinFromNativeToCRC21`, for **source coins** (`isSource = true`): [2](#0-1) 

The native coins are burned at lines 117–124 **before** `CallModuleCRC21` is invoked at line 126. If the contract has no code, `CallModuleCRC21` calls `CallEVM` → `ApplyMessage`. In go-ethereum / Ethermint, a call to a codeless address returns `(nil, gas, nil)` — success with empty data, `reverted = false`. Therefore `res.Failed()` is `false`, and `CallModuleCRC21` returns `nil` error: [3](#0-2) 

The function returns `nil`, the caller commits the state, and the user's native coins are permanently burned with no CRC21 tokens transferred.

For **non-source coins** (IBC tokens), the same pattern applies at lines 132–140: [4](#0-3) 

IBC tokens are sent to the dead contract address (line 132) before `mint_by_cronos_module` is called silently (line 137). The IBC tokens are permanently locked in the codeless address; no CRC21 tokens are minted.

The IBC conversion middleware calls this path on every inbound IBC packet for a mapped denom: [5](#0-4) 

---

### Impact Explanation

- **Source-coin path**: User's `cronos0x…` native coins are burned (irreversible bank operation) but no CRC21 tokens are transferred. Permanent, unrecoverable loss of source coins. Matches **Critical: unauthorized burn of CRC21/source-denom assets**.
- **Non-source-coin path**: IBC vouchers are sent to a codeless address and permanently locked; no CRC21 tokens are minted. Matches **Critical: unauthorized escrow/accounting change for IBC vouchers**.

Both impacts are triggered through the normal `MsgConvertVouchers` message surface and the IBC `OnRecvPacket` middleware path.

---

### Likelihood Explanation

The precondition is that a registered CRC21 contract is destroyed after registration. This is reachable without any system-level privilege compromise:

1. A contract owner (not CronosAdmin, not a validator) deploys a CRC21-compatible contract that includes a `selfdestruct` path.
2. CronosAdmin registers the mapping via `MsgUpdateTokenMapping` in good faith — `ensureContractCode` passes at this point.
3. The contract owner calls `selfdestruct` on their own contract. This is a normal EVM operation requiring no system privilege.
4. The KV-store mapping (`DenomToExternalContractKey` / `ContractToDenomKey`) remains intact; `GetContractByDenom` still returns the dead address.
5. Any subsequent `MsgConvertVouchers` or IBC inbound packet for that denom triggers the irreversible loss.

The contract owner is not a system admin, governance participant, or validator. No keys are leaked; no privileged role is compromised. The admin's registration action is legitimate and in good faith.

---

### Recommendation

Add a contract-existence check inside `ConvertCoinFromNativeToCRC21` **before** any bank operation, mirroring the guard already present at registration time:

```go
// At the top of ConvertCoinFromNativeToCRC21, after resolving `contract`:
if err := k.ensureContractCode(ctx, contract); err != nil {
    return fmt.Errorf("mapped contract has no code: %w", err)
}
```

This ensures that a stale mapping pointing to a destroyed contract is caught before any irreversible state change is committed.

---

### Proof of Concept

1. Deploy a Solidity contract implementing the CRC21 interface plus `function destroy() public { selfdestruct(payable(msg.sender)); }`.
2. CronosAdmin submits `MsgUpdateTokenMapping` with `denom = "cronos0x<contractAddr>"`, `contract = <contractAddr>`. `ensureContractCode` passes; mapping is written to KV store.
3. Contract owner calls `destroy()`. Contract bytecode is erased; the address becomes codeless.
4. A user holding `cronos0x<contractAddr>` native coins submits `MsgConvertVouchers`.
5. `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21`:
   - `GetContractByDenom` returns the dead address (mapping still present).
   - `isSource = true`.
   - `SendCoinsFromAccountToModule` + `BurnCoins` permanently burns the user's native coins.
   - `CallModuleCRC21(contract, "transfer_from_cronos_module", sender, amount)` → `CallEVM` → `ApplyMessage` on a codeless address → returns `(nil, gas, nil)`, `reverted = false`.
   - `res.Failed()` is `false`; `CallModuleCRC21` returns `nil`.
   - `ConvertCoinFromNativeToCRC21` returns `nil`.
6. **Result**: User's native coins are permanently burned; no CRC21 tokens are received. The loss is unrecoverable.

### Citations

**File:** x/cronos/keeper/keeper.go (L312-327)
```go
func (k Keeper) ensureContractCode(ctx sdk.Context, contract common.Address) error {
	if contract.Big().Cmp(big.NewInt(256)) < 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress,
			"crc21 contract must not be in precompile range: %s", contract.Hex())
	}
	resp, err := k.evmKeeper.Code(ctx, &evmtypes.QueryCodeRequest{
		Address: contract.Hex(),
	})
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "failed to query contract code (%s): %v", contract.Hex(), err)
	}
	if resp == nil || len(resp.Code) == 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidRequest, "no contract code at address (%s)", contract.Hex())
	}
	return nil
}
```

**File:** x/cronos/keeper/evm.go (L54-68)
```go
// CallModuleCRC21 call a method of ModuleCRC21 contract
func (k Keeper) CallModuleCRC21(ctx sdk.Context, contract common.Address, method string, args ...interface{}) ([]byte, error) {
	data, err := types.ModuleCRC21Contract.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	_, res, err := k.CallEVM(ctx, &contract, data, big.NewInt(0), DefaultGasCap)
	if err != nil {
		return nil, err
	}
	if res.Failed() {
		return nil, fmt.Errorf("call contract failed: %s, %s, %s", contract.Hex(), method, res.Ret)
	}
	return res.Ret, nil
}
```

**File:** x/cronos/keeper/evm.go (L115-129)
```go
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
```

**File:** x/cronos/keeper/evm.go (L130-141)
```go
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
```

**File:** x/cronos/middleware/conversion_middleware.go (L124-143)
```go
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
```
