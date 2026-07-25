### Title
Inflated `approveTx.gasLimit` in `lendAmount()` allows attacker to drain proposer KAIA when SwapTx reverts — (`kaiax/gasless/impl/getter.go`)

---

### Summary

`lendAmount()` computes the proposer's advance using `approveTx.Fee() = gasPrice × gasLimit`. Because no validation caps `approveTx.gasLimit`, an attacker can set it to the block gas limit (30 000 000), inflating the lend by ~650× the real approve cost. The SP4 invariant then forces `swapTx.amountRepay` and `swapTx.minAmountOut` to match the inflated figure, making the swap revert at execution time (actual DEX output < inflated `minAmountOut`). The LendTx has already settled; the proposer is never repaid.

---

### Finding Description

**`lendAmount()` — no gasLimit cap** [1](#0-0) 

`approveTxOrNil.Fee()` is `gasPrice × gasLimit` — the *maximum* possible fee, not the gas actually consumed. `isApproveTx()` validates only token whitelist, spender, and `amount == MaxUint256`; it never inspects `gasLimit`. [2](#0-1) 

`decodeFunctionCall()` likewise imposes no gasLimit constraint. [3](#0-2) 

**SP4 forces `amountRepay` to track the inflated value**

`VerifyExecutable` rejects any SwapTx whose `amountRepay` does not equal `repayAmount(approveTx, swapTx)`. [4](#0-3) 

`repayAmount = R1 + lendAmount`, so inflating `approveTx.gasLimit` inflates both `lendAmount` and `amountRepay` by the same factor. [5](#0-4) 

**Txpool forces `minAmountOut ≥ amountRepay`** [6](#0-5) 

With `amountRepay` inflated to ~0.03 KAIA, `minAmountOut` must be at least that large. The actual DEX output for a normal `amountIn` is far below this threshold, so the SwapTx reverts on-chain.

**LendTx is not atomic with SwapTx**

The bundle is `[LendTx, ApproveTx, SwapTx]`. Each transaction settles independently. A SwapTx revert does not roll back the already-confirmed LendTx. [7](#0-6) 

**Proposer net loss when SwapTx reverts**

```
lendAmount  = approveTx.gasLimit × gasPrice  +  swapTx.gasLimit × gasPrice
            = 30 000 000 × 1e9   +  swapTx.gasLimit × 1e9
            ≈ 30e15 wei  (0.03 KAIA)

block reward received by proposer
            = approveTx.gasUsed × gasPrice  +  swapTx.gasUsed × gasPrice
            ≈ 46 000 × 1e9  +  swapTx.gasUsed × 1e9
            ≈ negligible

net proposer loss ≈ (approveTx.gasLimit − approveTx.gasUsed) × gasPrice
                  ≈ (30 000 000 − 46 000) × 1e9
                  ≈ 0.03 KAIA per bundle
```

The attacker retains the gas refund `(gasLimit − gasUsed) × gasPrice` credited back to their account by the EVM.

---

### Impact Explanation

The proposer's KAIA balance is drained by the difference between the inflated `lendAmount` and the actual gas consumed by the ApproveTx. With `gasLimit = 30 000 000` and `gasPrice = 1e9`, the loss is ~0.03 KAIA per bundle. The attack is repeatable across blocks, causing cumulative unauthorized transfer of KAIA from the proposer to the attacker.

---

### Likelihood Explanation

The attacker submits two standard legacy transactions via public RPC. The only prerequisite under the default `BalanceCheckLevelAll` config is holding enough tokens to satisfy `amountIn ≥ requiredAmountIn(minAmountOut)` at admission time. [8](#0-7) 

The swap revert is guaranteed because `minAmountOut` is forced to equal the inflated `amountRepay`, which far exceeds what the DEX can return for any realistic `amountIn`. Price slippage, deadline timing, or simply setting `minAmountOut` above the liquidity ceiling all reliably trigger the revert. The attacker's tokens are returned on revert; only the proposer's KAIA is lost.

---

### Recommendation

Cap `lendAmount` to the actual intrinsic gas cost of the ApproveTx rather than its declared `gasLimit × gasPrice`. Concretely, replace `approveTxOrNil.Fee()` with `intrinsicGas(approveTx) × gasPrice`, where `intrinsicGas` is the statically computable minimum gas for a legacy ERC-20 `approve` call. Alternatively, enforce a hard upper bound on `approveTx.gasLimit` inside `isApproveTx()` (e.g., reject any ApproveTx whose `gasLimit` exceeds a configured maximum such as 100 000).

---

### Proof of Concept

```
gasLimit_attack  = 30_000_000
gasLimit_normal  = 46_000
gasPrice         = 1e9 wei

lendAmount_attack = 30_000_000 × 1e9 = 30e15 wei  (0.030 KAIA)
lendAmount_normal =     46_000 × 1e9 = 46e12 wei  (0.000046 KAIA)
ratio             ≈ 652×

amountRepay_attack = (21_000 + 30_000_000 + swapGasLimit) × 1e9  ≈ 0.030 KAIA
minAmountOut must be ≥ amountRepay_attack  → swap reverts on-chain

proposer net loss = lendAmount_attack − approveTx.gasUsed × gasPrice
                  ≈ (30_000_000 − 46_000) × 1e9
                  ≈ 0.02995 KAIA per attack bundle
```

Steps:
1. Craft `ApproveTx`: `to=whitelistedToken`, `data=approve(router, MaxUint256)`, `gasLimit=30_000_000`, `gasPrice=1e9`.
2. Compute `lendAmount` and `repayAmount` off-chain using the formulas in `getter.go`.
3. Craft `SwapTx`: `amountRepay=repayAmount` (SP4), `minAmountOut=amountRepay` (txpool gate), `amountIn=requiredAmountIn(minAmountOut)` (swap-amount gate), `deadline=far future`.
4. Submit both via `eth_sendRawTransaction`.
5. Bundle is promoted; proposer generates LendTx sending 0.03 KAIA to attacker.
6. ApproveTx executes; SwapTx reverts (actual DEX output ≪ inflated `minAmountOut`).
7. Proposer's KAIA balance is reduced by ~0.03 KAIA; attacker retains the gas refund.

### Citations

**File:** kaiax/gasless/impl/getter.go (L79-86)
```go
func (g *GaslessModule) isApproveTx(args *ApproveArgs) bool {
	g.gaslessInfoMu.RLock()
	defer g.gaslessInfoMu.RUnlock()

	return g.allowedTokens[args.Token] && // A1
		g.swapRouter == args.Spender && // A3
		args.Amount.Cmp(abi.MaxUint256) == 0 // A4
}
```

**File:** kaiax/gasless/impl/getter.go (L182-193)
```go
func decodeFunctionCall(tx *types.Transaction, method abi.Method) (common.Address, map[string]interface{}, bool) {
	if tx.Type() != types.TxTypeLegacyTransaction || // not legacy tx: unable to statically determine the max gas fee.
		tx.To() == nil || // not a contract call.
		len(tx.Data()) < 4 || // too short to be a contract call.
		!bytes.Equal(tx.Data()[:4], method.ID) { // not the target function.
		return common.Address{}, nil, false
	}

	inputs := make(map[string]interface{})
	err := method.Inputs.UnpackIntoMap(inputs, tx.Data()[4:])
	return *tx.To(), inputs, err == nil
}
```

**File:** kaiax/gasless/impl/getter.go (L260-263)
```go
	// SP4.
	if swapArgs.AmountRepay.Cmp(repayAmount(approveTxOrNil, swapTx)) != 0 {
		return fmt.Errorf("%w: got %s, expected %s", ErrIncorrectRepayAmount, swapArgs.AmountRepay.String(), repayAmount(approveTxOrNil, swapTx).String())
	}
```

**File:** kaiax/gasless/impl/getter.go (L346-358)
```go
func lendAmount(approveTxOrNil, swapTx *types.Transaction) *big.Int {
	r := new(big.Int)

	// R2 = ApproveTx.Fee() if exists
	if approveTxOrNil != nil {
		r.Add(r, approveTxOrNil.Fee())
	}

	// R3 = SwapTx.Fee()
	r.Add(r, swapTx.Fee())

	// LendAmount = R2 + R3
	return r
```

**File:** kaiax/gasless/impl/getter.go (L361-367)
```go
func repayAmount(approveTxOrNil, swapTx *types.Transaction) *big.Int {
	// R1 = LendTx.Fee() = SwapTx.GasPrice() * TxGas
	r1 := new(big.Int).Mul(swapTx.GasPrice(), new(big.Int).SetUint64(params.TxGas))

	// RepayAmount = R1 + R2 + R3
	return new(big.Int).Add(r1, lendAmount(approveTxOrNil, swapTx))
}
```

**File:** kaiax/gasless/impl/tx_pool.go (L115-120)
```go
	// tx.minAmountOut >= tx.amountRepay
	minAmountOut := swapArgs.MinAmountOut
	amountRepay := swapArgs.AmountRepay
	if minAmountOut.Cmp(amountRepay) < 0 {
		return fmt.Errorf("insufficient minAmountOut: minAmountOut=%s, amountRepay=%s", minAmountOut.String(), amountRepay.String())
	}
```

**File:** kaiax/gasless/README.md (L33-36)
```markdown
- Per sender, if exists, GaslessApproveTx is relocated before GaslessSwapTx.
- LendTxGenerator is prepended before GaslessApproveTx.
- A new bundle is generated which contain either `[LendTxGenerator, GaslessApproveTx, GaslessSwapTx]` or `[LendTxGenerator, GaslessSwapTx]`
- If the bundle has conflict with any previous bundles, it is excluded from the returned bundle list.
```

**File:** kaiax/gasless/config.go (L80-96)
```go
func DefaultGaslessConfig() *GaslessConfig {
	return &GaslessConfig{
		AllowedTokens:         nil,
		Disable:               false,
		MaxBundleTxsInPending: 100,
		MaxBundleTxsInQueue:   200,
		BalanceCheckLevel:     BalanceCheckLevelAll,
	}
}

func (cfg *GaslessConfig) ShouldCheckToken() bool {
	return cfg.BalanceCheckLevel >= BalanceCheckLevelTokenBalanceAndAllowance
}

func (cfg *GaslessConfig) ShouldCheckSwapAmount() bool {
	return cfg.BalanceCheckLevel >= BalanceCheckLevelSwapAmount
}
```
