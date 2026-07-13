I need to trace the full attack path through the production code before rendering a verdict.

**Step 1 — Entry point: `OnRecvPacket`**

The middleware's `OnRecvPacket` first calls the underlying IBC transfer module (which mints vouchers to `data.Receiver`), then calls `ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, ...)` with the raw receiver string from the packet. [1](#0-0) 

**Step 2 — `ConvertVouchersToEvmCoins`: bech32 decode, no zero-address guard**

```go
acc, err := sdk.AccAddressFromBech32(from)   // succeeds for bech32(zero_address)
...
err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
```

`sdk.AccAddressFromBech32` accepts any valid bech32 string, including the encoding of 20 zero bytes (e.g. `crc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs9gg3z`). There is no `sender != zero` guard here. [2](#0-1) 

**Step 3 — `ConvertCoinFromNativeToCRC21`: no zero-address guard on `sender`**

For a non-source IBC denom the function:
1. Calls `bankKeeper.SendCoins(ctx, sdk.AccAddress(sender.Bytes()), sdk.AccAddress(contract.Bytes()), coins)` — the zero address already holds the vouchers (minted by the IBC transfer module in step 1), so this succeeds.
2. Calls `CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())` — `sender` is `address(0)`. [3](#0-2) 

**Step 4 — `ModuleCRC21.mint_by_cronos_module`: no zero-address check**

```solidity
function mint_by_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    mint(addr, amount);   // delegates to DSToken.mint — no address(0) guard
}
```

`DSToken.mint` (dapphub/ds-token) simply does `balanceOf[guy] += wad; totalSupply += wad;` with **no** `require(guy != address(0))` check, unlike OpenZeppelin ERC20. The call succeeds and tokens are credited to `address(0)`. [4](#0-3) 

**Step 5 — Net state after the attack**

| Asset | Location | Accessible? |
|---|---|---|
| IBC vouchers | Locked in CRC21 contract address | No |
| CRC21 EVM tokens | Minted to `address(0)` | No |
| CRC21 `totalSupply` | Inflated by `amount` | — |

The IBC vouchers are permanently locked in the contract's Cosmos account, and the corresponding EVM tokens are permanently inaccessible at `address(0)`. The `totalSupply` of the CRC21 token is inflated without any reachable holder, breaking the invariant that `totalSupply == sum of accessible balances`.

---

### Title
Minting CRC21 tokens to `address(0)` via IBC packet with zero-address receiver — (`x/cronos/keeper/evm.go`, `x/cronos/middleware/conversion_middleware.go`)

### Summary
Any user on a counterparty IBC chain can send a transfer packet whose `receiver` field is the bech32 encoding of the 20-byte zero address. The Cronos IBC conversion middleware passes this address through to `ConvertCoinFromNativeToCRC21` without a zero-address guard. The DSToken-based `ModuleCRC21` contract also lacks a zero-address guard in `mint_by_cronos_module`, so EVM tokens are minted to `address(0)` and permanently locked, while the corresponding IBC vouchers are locked in the contract's Cosmos account.

### Finding Description
The attack path is entirely within the IBC receive flow:

1. Attacker sends an IBC fungible-token transfer to Cronos with `receiver = bech32(0x0000…0000)` (e.g. `crc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs9gg3z`).
2. `IBCConversionModule.OnRecvPacket` calls the underlying transfer module, which mints IBC vouchers to the zero Cosmos address (not a blocked address in the bank module).
3. The middleware then calls `ConvertVouchersToEvmCoins(cacheCtx, data.Receiver, coins)`.
4. `ConvertVouchersToEvmCoins` decodes the bech32 string successfully (20 zero bytes is a valid address) and calls `ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), ...)` with `sender = address(0)`.
5. `bankKeeper.SendCoins` moves the vouchers from the zero Cosmos address to the CRC21 contract address (succeeds because the zero address holds the freshly minted vouchers).
6. `CallModuleCRC21(ctx, contract, "mint_by_cronos_module", address(0), amount)` is called.
7. `DSToken.mint(address(0), amount)` succeeds — ds-token has no `require(guy != address(0))` guard — crediting `balanceOf[address(0)]` and inflating `totalSupply`.

No privileged access, no leaked keys, and no external dependency failure is required.

### Impact Explanation
- IBC vouchers are permanently locked in the CRC21 contract's Cosmos account with no recovery path.
- CRC21 EVM tokens are minted to `address(0)` and are permanently inaccessible.
- The CRC21 `totalSupply` is inflated without any reachable holder, corrupting the token's accounting invariant.
- Any user on any connected IBC chain can trigger this for any auto-deployed or mapped CRC21 token, repeatedly, at the cost of their own transferred tokens. This enables griefing of token economics (e.g. inflating `totalSupply` to manipulate price oracles or ratio-based protocols).

This matches the High impact category: *Corruption of token mappings, denom/contract binding, IBC channel/accounting state … with direct security impact* and *Unauthorized … balance/accounting change for … IBC vouchers, CRC21 … assets*.

### Likelihood Explanation
- Requires only the ability to submit an IBC transfer from any connected chain — fully unprivileged.
- `EnableAutoDeployment` is the default production setting, so no pre-existing mapping is needed.
- The bech32 encoding of the zero address is a valid, well-formed string that passes all SDK validation.

### Recommendation
1. **In `ConvertCoinFromNativeToCRC21`** (or `ConvertVouchersToEvmCoins`): add an explicit guard:
   ```go
   if (sender == common.Address{}) {
       return fmt.Errorf("zero EVM address is not a valid recipient")
   }
   ```
2. **In `ModuleCRC21.mint_by_cronos_module`**: add a Solidity-level guard:
   ```solidity
   require(addr != address(0), "mint to zero address");
   ```
   This provides defence-in-depth even if the Go-layer check is bypassed.

### Proof of Concept
```
1. On any IBC-connected chain, submit:
   MsgTransfer{
     receiver: "crc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs9gg3z",  // bech32(0x000...000)
     token:    { denom: "ibc/XXXX", amount: "1000" },
   }

2. On Cronos, after the packet is relayed:
   - Query bank balance of crc1qqq...qs9gg3z → 0 (vouchers moved to contract)
   - Query CRC21.balanceOf(address(0)) → 1000
   - Query CRC21.totalSupply() → 1000 (inflated, no accessible holder)
   - Query bank balance of CRC21 contract cosmos address → 1000 (vouchers locked)
```

### Citations

**File:** x/cronos/middleware/conversion_middleware.go (L106-146)
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
