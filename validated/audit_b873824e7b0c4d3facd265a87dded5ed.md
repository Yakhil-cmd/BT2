Tracing the full execution path carefully before rendering a verdict.

**Flow:**

1. `IBCConversionModule.OnRecvPacket` calls `im.app.OnRecvPacket` (standard IBC transfer module), which credits IBC vouchers to `data.Receiver` — any valid bech32 address, including a CRC20 contract's cosmos address. No guard blocks contract addresses here; only registered module accounts are in `BlockedAddrs()`.

2. If `canBeConverted` is true, `im.cronoskeeper.ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, ...)` is called with `data.Receiver` = the contract's bech32 address. [1](#0-0) 

3. `ConvertVouchersToEvmCoins` parses `from` via `sdk.AccAddressFromBech32` — succeeds for any valid bech32 — then calls `ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, ...)`. No check that `acc` is not a contract address. [2](#0-1) 

4. Inside `ConvertCoinFromNativeToCRC21` (non-source/IBC-voucher path):
   - `bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)` — when `sender` IS the contract's EVM address, this is a self-transfer (same address), which succeeds.
   - `CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, amount)` — mints CRC20 tokens to `sender` = the contract's own EVM address. [3](#0-2) 

5. `mint_by_cronos_module` in the Solidity contract accepts any `addr` argument, including the contract's own address. [4](#0-3) 

**Result of the attack:**
- IBC vouchers are credited to the contract's cosmos address (locked — no recovery path).
- CRC20 tokens are minted to the contract's own EVM `balanceOf` (locked — the contract has no function to spend its own balance).
- CRC20 total supply is inflated by the minted amount with no corresponding user holding.

**Guards checked and absent:**
- `ConvertVouchersToEvmCoins` only validates bech32 format, not whether the address is a contract. [5](#0-4) 
- `BlockedAddrs()` only covers registered module accounts, not EVM contract addresses. [6](#0-5) 
- `ConvertCoinFromNativeToCRC21` has no check that `sender != contract`. [7](#0-6) 
- The `BankKeeper` interface used by the cronos keeper does not expose `BlockedAddr`. [8](#0-7) 

---

### Title
IBC Packet with CRC20 Contract Address as Receiver Causes Permanent Token Lock and CRC20 Supply Inflation — (`x/cronos/middleware/conversion_middleware.go`, `x/cronos/keeper/ibc.go`, `x/cronos/keeper/evm.go`)

### Summary
An unprivileged IBC counterparty can craft a packet whose `receiver` field is the bech32 encoding of a registered CRC20/CRC21 contract address. `IBCConversionModule.OnRecvPacket` passes this address directly to `ConvertVouchersToEvmCoins`, which in turn calls `ConvertCoinFromNativeToCRC21` with the contract as both sender and mint target. The result is: IBC vouchers permanently locked at the contract's cosmos address, and CRC20 tokens minted to the contract's own EVM balance with no recovery path, inflating total supply.

### Finding Description
`IBCConversionModule.OnRecvPacket` extracts `data.Receiver` from the IBC packet and passes it verbatim to `ConvertVouchersToEvmCoins`. That function parses it as a bech32 address (succeeds for any valid address, including a contract's cosmos address) and derives the EVM address via `common.BytesToAddress(acc.Bytes())`. This EVM address is forwarded as `sender` to `ConvertCoinFromNativeToCRC21`.

In the non-source (IBC voucher) branch of `ConvertCoinFromNativeToCRC21`:
1. `bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)` — when `sender == contract`, this is a self-transfer that succeeds.
2. `CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, amount)` — mints CRC20 tokens to `sender` = the contract's own address.

Neither `ConvertVouchersToEvmCoins` nor `ConvertCoinFromNativeToCRC21` validates that the receiver/sender is not a contract address. `BlockedAddrs()` only covers registered Cosmos module accounts, not EVM contract addresses.

### Impact Explanation
- **CRC20 total supply inflation**: tokens are minted to the contract's own `balanceOf` with no user receiving them. The supply is permanently inflated.
- **IBC voucher accounting corruption**: the IBC vouchers are credited to the contract's cosmos address and then "sent to itself" — they are permanently locked there with no recovery path.
- Both assets (IBC vouchers and CRC20 tokens) are irrecoverably locked. This is an unauthorized balance/accounting change for IBC vouchers and CRC20 assets.

### Likelihood Explanation
The `receiver` field in an IBC `FungibleTokenPacketData` is fully attacker-controlled. Any party that can initiate an IBC transfer from a counterparty chain can set `receiver` to the bech32 encoding of any registered CRC20 contract on Cronos. No privileged access is required. The attack is repeatable and can target any mapped denom.

### Recommendation
In `ConvertVouchersToEvmCoins` (or at the `IBCConversionModule.OnRecvPacket` call site), validate that `data.Receiver` does not correspond to a known contract address before invoking conversion. Concretely:

```go
// After parsing acc from bech32:
evmAddr := common.BytesToAddress(acc.Bytes())
if _, found := k.GetDenomByContract(ctx, evmAddr); found {
    return fmt.Errorf("receiver %s is a contract address and cannot receive converted vouchers", from)
}
```

Alternatively, check whether the account has EVM code deployed at that address before proceeding with conversion.

### Proof of Concept
1. Deploy or identify a registered CRC21 contract at EVM address `0xCONTRACT` on Cronos, mapped to IBC denom `ibc/XXXX`.
2. Compute `receiver = sdk.AccAddress(common.HexToAddress("0xCONTRACT").Bytes()).String()` — the bech32 encoding of the contract's cosmos address.
3. From a counterparty chain, send an IBC transfer of `ibc/XXXX` tokens with `receiver` set to the value from step 2.
4. On Cronos, `IBCConversionModule.OnRecvPacket` processes the packet:
   - Standard IBC transfer credits `ibc/XXXX` vouchers to the contract's cosmos address.
   - `ConvertVouchersToEvmCoins` calls `ConvertCoinFromNativeToCRC21` with `sender = 0xCONTRACT`.
   - `mint_by_cronos_module(0xCONTRACT, amount)` executes successfully.
5. Assert: `balanceOf[0xCONTRACT]` on the CRC21 contract equals the transferred amount; `totalSupply` is inflated; IBC vouchers are locked at the contract's cosmos address; no user received any tokens.

### Citations

**File:** x/cronos/middleware/conversion_middleware.go (L135-143)
```go
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

**File:** x/cronos/keeper/ibc.go (L21-64)
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
```

**File:** x/cronos/keeper/evm.go (L91-113)
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

**File:** contracts/src/ModuleCRC21.sol (L36-39)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }
```

**File:** app/app.go (L1365-1371)
```go
func (app *App) BlockedAddrs() map[string]bool {
	blockedAddrs := make(map[string]bool)
	for acc := range maccPerms {
		blockedAddrs[authtypes.NewModuleAddress(acc).String()] = !allowedReceivingModAcc[acc]
	}

	return blockedAddrs
```

**File:** x/cronos/types/interfaces.go (L23-33)
```go
type BankKeeper interface {
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SendCoins(ctx context.Context, senderAddr, recipientAddr sdk.AccAddress, amt sdk.Coins) error

	GetDenomMetaData(ctx context.Context, denom string) (banktypes.Metadata, bool)
	SetDenomMetaData(ctx context.Context, denomMetaData banktypes.Metadata)
}
```
