### Title
Missing Zero-Address Guard in `mint_by_cronos_module` Allows CRC21/CRC20 totalSupply Inflation via IBC Conversion Middleware - (File: contracts/src/ModuleCRC21.sol, x/cronos/keeper/evm.go)

### Summary
`ModuleCRC21.sol` and `ModuleCRC20.sol` inherit DSToken's `mint(address guy, uint wad)` which contains no zero-address guard. The keeper's `ConvertCoinFromNativeToCRC21` passes the `sender` address directly to `mint_by_cronos_module` without validating it is non-zero. An unprivileged attacker can send an IBC transfer to the bech32-encoded zero address on Cronos, causing the IBC conversion middleware to invoke `mint_by_cronos_module(address(0), amount)`, permanently inflating the CRC21 `totalSupply` while locking the minted tokens at `address(0)`.

### Finding Description

`ModuleCRC21.sol` delegates minting to DSToken's `mint`:

```solidity
function mint_by_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    mint(addr, amount);   // DSToken: no require(addr != address(0))
}
``` [1](#0-0) 

DSToken's `mint` simply increments `balanceOf[guy]` and `totalSupply` with no zero-address check. The same pattern exists in `ModuleCRC20.sol`. [2](#0-1) 

The keeper's `ConvertCoinFromNativeToCRC21` (non-source path) passes `sender` directly:

```go
_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
``` [3](#0-2) 

`sender` originates from `ConvertVouchersToEvmCoins`, which derives it from `sdk.AccAddressFromBech32(from)`: [4](#0-3) 

The IBC conversion middleware calls `ConvertVouchersToEvmCoins` with `data.Receiver` taken directly from the IBC packet — fully attacker-controlled: [5](#0-4) 

### Impact Explanation

An attacker sends an IBC transfer to Cronos with `receiver = bech32(address(0))` and a denom that is mapped to a CRC21 contract. The attack sequence:

1. `im.app.OnRecvPacket` credits `address(0)` (Cosmos side) with the IBC vouchers.
2. Middleware calls `ConvertVouchersToEvmCoins(ctx, bech32(address(0)), coins)`.
3. `ConvertCoinFromNativeToCRC21(ctx, address(0), coin, autoDeploy)` is invoked.
4. `bankKeeper.SendCoins(ctx, zero_cosmos_addr, contract_cosmos_addr, coins)` succeeds — the zero address holds the vouchers from step 1.
5. `CallModuleCRC21(ctx, contract, "mint_by_cronos_module", address(0), amount)` executes.
6. DSToken's `mint(address(0), amount)` increments `balanceOf[address(0)]` and `totalSupply` with no revert.

Result: CRC21 `totalSupply` is permanently inflated by `amount`; the minted tokens are irrecoverable at `address(0)`; the IBC vouchers are locked inside the CRC21 contract with no corresponding redeemable CRC21 tokens in circulation. This is an unauthorized accounting change for CRC21 assets.

### Likelihood Explanation

Any unprivileged actor who can initiate an IBC transfer to Cronos can trigger this. No keys, governance, or admin access are required. The only prerequisite is that the transferred denom is mapped to a CRC21 contract (which is the normal operating condition for IBC vouchers on Cronos). The attacker sacrifices the transferred tokens but can inflate `totalSupply` by an arbitrary amount.

### Recommendation

Add a zero-address guard in `mint_by_cronos_module` in both `ModuleCRC21.sol` and `ModuleCRC20.sol`:

```solidity
function mint_by_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    require(addr != address(0), "mint to the zero address");
    mint(addr, amount);
}
```

Additionally, add a zero-address check in `ConvertCoinFromNativeToCRC21` in `x/cronos/keeper/evm.go` before calling `mint_by_cronos_module`:

```go
if sender == (common.Address{}) {
    return fmt.Errorf("cannot convert coins to zero address")
}
```

### Proof of Concept

1. Deploy or identify a CRC21 contract mapped to IBC denom `ibc/XXXX`.
2. From an external chain, initiate an IBC transfer of `N ibc/XXXX` tokens to Cronos with `receiver = crc10000000000000000000000000000000000000000` (bech32 of 20 zero bytes).
3. Observe that `OnRecvPacket` succeeds and the middleware calls `ConvertVouchersToEvmCoins`.
4. Query the CRC21 contract's `totalSupply` — it has increased by `N`.
5. Query `balanceOf(address(0))` on the CRC21 contract — it equals `N`.
6. The `N` IBC vouchers are now locked in the CRC21 contract with no redeemable CRC21 tokens in circulation, permanently corrupting the token accounting.

### Citations

**File:** contracts/src/ModuleCRC21.sol (L36-39)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }
```

**File:** contracts/src/ModuleCRC20.sol (L31-34)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }
```

**File:** x/cronos/keeper/evm.go (L136-140)
```go
		// mint crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "mint_by_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
```

**File:** x/cronos/keeper/ibc.go (L21-25)
```go
func (k Keeper) ConvertVouchersToEvmCoins(ctx sdk.Context, from string, coins sdk.Coins) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}
```

**File:** x/cronos/middleware/conversion_middleware.go (L134-143)
```go
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
