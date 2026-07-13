### Title
Predictable `DeployModuleCRC21` Address Allows Attacker to Permanently Block IBC Voucher Auto-Conversion - (File: `x/cronos/keeper/evm.go`)

### Summary
`DeployModuleCRC21` computes the deployed CRC21 contract address deterministically as `crypto.CreateAddress(EVMModuleAddress, nonce)`. An unprivileged attacker can observe the current nonce of `EVMModuleAddress`, compute the next deployment address, and pre-occupy it via `CREATE2`. All subsequent auto-deployment attempts for any new IBC/Gravity denom will fail, permanently blocking the IBC voucher-to-CRC21 conversion flow when `EnableAutoDeployment` is `true`.

---

### Finding Description

`DeployModuleCRC21` in `x/cronos/keeper/evm.go` deploys the embedded CRC21 contract by calling `CallEVM` with `to = nil` (a `CREATE` call from `types.EVMModuleAddress`):

```go
// x/cronos/keeper/evm.go:71-88
func (k Keeper) DeployModuleCRC21(ctx sdk.Context, denom string) (common.Address, error) {
    ...
    msg, res, err := k.CallEVM(ctx, nil, data, big.NewInt(0), DefaultGasCap)
    ...
    return crypto.CreateAddress(types.EVMModuleAddress, msg.Nonce), nil
}
``` [1](#0-0) 

The resulting address is `keccak256(rlp(EVMModuleAddress, nonce))[12:]` — fully deterministic from public state. `EVMModuleAddress` is a module-level constant and its EVM nonce is readable from chain state.

`CallEVM` reads the nonce immediately before constructing the message:

```go
// x/cronos/keeper/evm.go:25-26
nonce := k.evmKeeper.GetNonce(ctx, types.EVMModuleAddress)
msg := &core.Message{From: types.EVMModuleAddress, Nonce: nonce, ...}
``` [2](#0-1) 

The EVM `CREATE` opcode fails if the target address already has non-empty code or a non-zero nonce. An attacker can use `CREATE2` from a factory contract to deploy an arbitrary contract at the exact address `crypto.CreateAddress(EVMModuleAddress, currentNonce)` before any legitimate auto-deployment occurs.

When `DeployModuleCRC21` subsequently fails, `ConvertCoinFromNativeToCRC21` propagates the error:

```go
// x/cronos/keeper/evm.go:102-107
contract, err = k.DeployModuleCRC21(ctx, coin.Denom)
if err != nil {
    return err
}
if err = k.SetAutoContractForDenom(ctx, coin.Denom, contract); err != nil {
    return err
}
``` [3](#0-2) 

Because `SetAutoContractForDenom` is never reached, the denom remains unmapped. `OnRecvVouchers` wraps the call in a `cacheCtx` that is not committed on error, meaning the EVM nonce increment is also reverted:

```go
// x/cronos/keeper/keeper.go:296-301
func (k Keeper) OnRecvVouchers(ctx sdk.Context, tokens sdk.Coins, receiver string) error {
    cacheCtx, commit := ctx.CacheContext()
    if err := k.ConvertVouchersToEvmCoins(cacheCtx, receiver, tokens); err != nil {
        return err
    }
    commit()
    return nil
}
``` [4](#0-3) 

Because the cache context is discarded on error, `EVMModuleAddress`'s nonce is never advanced. Every subsequent auto-deployment attempt targets the same pre-occupied address and fails identically. The attacker only needs to occupy **one** address to permanently block all future auto-deployments for all new denoms.

---

### Impact Explanation

When `EnableAutoDeployment = true`, every incoming IBC or Gravity token for a new denom triggers `DeployModuleCRC21` via `OnRecvVouchers` → `ConvertVouchersToEvmCoins` → `ConvertCoinFromNativeToCRC21`. With the target address pre-occupied, all such conversions fail permanently. Users' IBC vouchers arrive on Cronos but cannot be wrapped into CRC21 tokens. The same failure occurs for `MsgConvertVouchers` messages. This is a **permanent, long-lived inability for honest users to process valid bridge/conversion flows** — matching the High impact tier. [5](#0-4) 

---

### Likelihood Explanation

- `EnableAutoDeployment` is a chain parameter that can be `true` on mainnet.
- `EVMModuleAddress` is a public constant; its EVM nonce is readable via standard `eth_getTransactionCount`.
- The attacker requires only a single EVM transaction (a `CREATE2` factory call) costing normal gas fees.
- No privileged access, leaked keys, or cryptographic assumptions are required.
- The attack is permanent: the nonce never advances past the collision because the cache context is reverted on failure.

---

### Recommendation

Before calling `CallEVM` for deployment, check whether the computed target address is already occupied:

```go
targetAddr := crypto.CreateAddress(types.EVMModuleAddress, nonce)
if k.evmKeeper.GetCode(ctx, targetAddr) != nil {
    // advance nonce or return a descriptive error
}
```

Alternatively, use `CREATE2` with a denom-derived salt so the deployment address is bound to the denom and cannot be pre-empted without knowing the exact denom in advance. A salt of `keccak256(denom)` would make the address unique per denom and unpredictable to an attacker who does not know which denom will be registered next.

---

### Proof of Concept

1. Query `EVMModuleAddress` nonce: `eth_getTransactionCount(EVMModuleAddress, "latest")` → `N`.
2. Compute `targetAddr = crypto.CreateAddress(EVMModuleAddress, N)`.
3. Deploy a factory contract and call `factory.deployAt(targetAddr, salt)` using `CREATE2` such that the resulting address equals `targetAddr`. This is achievable by brute-forcing `salt` off-chain.
4. Confirm `eth_getCode(targetAddr)` is non-empty.
5. Send any IBC transfer of a new denom to Cronos (or submit `MsgConvertVouchers` for a new denom with `EnableAutoDeployment = true`).
6. Observe that `OnRecvVouchers` → `DeployModuleCRC21` fails with a contract-deploy error, the denom remains unmapped, and the IBC acknowledgement carries an error. The nonce of `EVMModuleAddress` is unchanged, so every subsequent attempt for any new denom hits the same occupied address and fails identically. [6](#0-5) [4](#0-3)

### Citations

**File:** x/cronos/keeper/evm.go (L24-39)
```go
func (k Keeper) CallEVM(ctx sdk.Context, to *common.Address, data []byte, value *big.Int, gasLimit uint64) (*core.Message, *evmtypes.EVMResult, error) {
	nonce := k.evmKeeper.GetNonce(ctx, types.EVMModuleAddress)
	msg := &core.Message{
		From:            types.EVMModuleAddress,
		To:              to,
		Nonce:           nonce,
		Value:           value, // amount
		GasLimit:        gasLimit,
		GasPrice:        big.NewInt(0),
		GasFeeCap:       nil,
		GasTipCap:       nil, // gasPrice
		Data:            data,
		AccessList:      nil, // accessList
		SkipNonceChecks: false,
	}
	ret, err := k.evmKeeper.ApplyMessage(ctx, msg, nil, true)
```

**File:** x/cronos/keeper/evm.go (L71-88)
```go
func (k Keeper) DeployModuleCRC21(ctx sdk.Context, denom string) (common.Address, error) {
	ctor, err := types.ModuleCRC21Contract.ABI.Pack("", denom, uint8(0), false)
	if err != nil {
		return common.Address{}, err
	}
	data := types.ModuleCRC21Contract.Bin
	data = append(data, ctor...)

	msg, res, err := k.CallEVM(ctx, nil, data, big.NewInt(0), DefaultGasCap)
	if err != nil {
		return common.Address{}, err
	}

	if res.Failed() {
		return common.Address{}, fmt.Errorf("contract deploy failed: %s", res.Ret)
	}
	return crypto.CreateAddress(types.EVMModuleAddress, msg.Nonce), nil
}
```

**File:** x/cronos/keeper/evm.go (L98-111)
```go
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
```

**File:** x/cronos/keeper/keeper.go (L289-302)
```go
// OnRecvVouchers try to convert ibc voucher to evm coins, revert the state in case of failure.
// Callers are responsible for logging or surfacing the returned error.
func (k Keeper) OnRecvVouchers(
	ctx sdk.Context,
	tokens sdk.Coins,
	receiver string,
) error {
	cacheCtx, commit := ctx.CacheContext()
	if err := k.ConvertVouchersToEvmCoins(cacheCtx, receiver, tokens); err != nil {
		return err
	}
	commit()
	return nil
}
```

**File:** x/cronos/keeper/ibc.go (L59-64)
```go
		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
```
