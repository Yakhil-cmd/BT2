### Title
Gasless Swap Proposer Fund Loss via DEX Price Manipulation Between Txpool Admission and Block Execution — (`kaiax/gasless/impl/tx_pool.go`)

---

### Summary

The `checkBalanceForSwap` function in the gasless module verifies `amountIn >= getAmountIn(minAmountOut)` against the live DEX price only at txpool admission time. At block-building time, `VerifyExecutable` performs only structural checks (nonces, repay amounts, token/spender addresses) and never re-queries the DEX price. An attacker who submits a valid gasless swap transaction and then manipulates the DEX price before the block is sealed causes the `SwapTx` to revert on-chain while the `LendTx` — which already transferred KAIA from the proposer to the attacker — has already executed and cannot be rolled back. The proposer loses the lent KAIA; the attacker retains both the lent KAIA and their original tokens.

---

### Finding Description

**Root cause — admission-time-only DEX price check:**

`checkBalanceForSwap` in `kaiax/gasless/impl/tx_pool.go` performs the following check at txpool admission:

```
tx.minAmountOut >= tx.amountRepay          // always enforced
tx.amountIn >= gsr.getAmountIn(minAmountOut) // only when ShouldCheckSwapAmount()
``` [1](#0-0) 

The second check calls `routerContract.GetAmountIn(nil, token, minAmountOut)` against the **current** chain state at admission time. It is never repeated.

**Block-building path — no DEX price re-check:**

At block-building time, `ExtractTxBundles` calls `IsExecutable` → `VerifyExecutable`. `VerifyExecutable` checks only:
- Nonces (SP3)
- Repay amount equality (SP4)
- Sender/token/spender identity (AP1, SP1, SP2)

It does **not** re-query the DEX price. [2](#0-1) 

**Bundle construction — no execution simulation:**

`ExtractTxBundles` constructs the bundle `[LendTx, ApproveTx, SwapTx]` and includes it in the block without simulating whether `SwapTx` will succeed at the current DEX price. [3](#0-2) 

**LendTx is not atomic with SwapTx:**

`GetLendTxGenerator` creates a standard `TxTypeEthereumDynamicFee` transfer of `lendAmount` KAIA from the proposer to the user. This is an independent transaction; if `SwapTx` reverts, the `LendTx` state change is **not** rolled back. [4](#0-3) 

`lendAmount = ApproveTx.Fee() + SwapTx.Fee()`: [5](#0-4) 

**Exploit flow:**

1. Attacker submits a gasless `SwapTx` with `minAmountOut` set to a value achievable at the current DEX price P₀ (passes `checkBalanceForSwap`).
2. Attacker manipulates the DEX pool in a subsequent block (e.g., large buy of KAIA), moving the price to P₁ where `amountIn < getAmountIn(minAmountOut)`.
3. Proposer calls `ExtractTxBundles`; `VerifyExecutable` passes (no DEX price check).
4. Block is sealed with bundle `[LendTx, ApproveTx, SwapTx]`.
5. `LendTx` executes: proposer transfers `lendAmount` KAIA to attacker. ✓
6. `ApproveTx` executes: attacker approves router. ✓
7. `SwapTx` executes: DEX cannot deliver `minAmountOut` KAIA for `amountIn` tokens at price P₁ → **reverts**.
8. Attacker retains original tokens **and** the `lendAmount` KAIA. Proposer's KAIA is gone.

---

### Impact Explanation

The block proposer (validator) suffers an unauthorized loss of KAIA equal to `lendAmount = ApproveTx.Fee() + SwapTx.Fee()` per exploited bundle. The attacker receives this KAIA for free and keeps their tokens. This is a direct, unauthorized transfer of KAIA from a system participant (the proposer) to the attacker, matching the "Unauthorized transfer … affecting KAIA … or system-managed funds" impact gate.

---

### Likelihood Explanation

- **Trigger is unprivileged**: any user can submit a gasless swap transaction.
- **Price manipulation is standard**: a sandwich-style DEX trade is a well-known, capital-accessible technique.
- **No re-check at execution**: the code path from `ExtractTxBundles` → `IsExecutable` → `VerifyExecutable` contains zero DEX price queries, so the window between admission and block sealing is fully exploitable.
- **Repeatable**: the attacker can repeat the attack across multiple blocks, draining the proposer incrementally.

---

### Recommendation

1. **Re-run the DEX price check at block-building time**: inside `ExtractTxBundles` (or a new pre-execution validation step), call `routerContract.GetAmountIn(token, minAmountOut)` against the current state and skip the bundle if `amountIn < requiredAmountIn`.
2. **Implement bundle atomicity**: if `SwapTx` reverts, revert the entire bundle (including `LendTx`) so the proposer's KAIA is never at risk. This requires a protocol-level mechanism (e.g., a system precompile or a wrapper contract) to make the three transactions atomic.
3. **Alternatively, have the GaslessSwapRouter contract hold the lent KAIA in escrow** and release it to the proposer only upon successful swap, so a revert never leaves the proposer out-of-pocket.

---

### Proof of Concept

```
// Setup
gasPrice  = 50 Gkei
R2        = 100_000 * gasPrice   // ApproveTx fee
R3        = 500_000 * gasPrice   // SwapTx fee
lendAmt   = R2 + R3              // proposer lends this to attacker

// Step 1 – attacker submits gasless swap tx at price P0
SwapTx: amountIn=X, minAmountOut=amountRepay+1, amountRepay=R1+R2+R3
// checkBalanceForSwap passes: getAmountIn(minAmountOut) <= X at P0

// Step 2 – attacker buys large amount of KAIA on DEX, moving price to P1
// At P1: getAmountIn(minAmountOut) > X  (amountIn is now insufficient)

// Step 3 – proposer builds block
// ExtractTxBundles → IsExecutable → VerifyExecutable: PASSES (no DEX price check)
// Bundle [LendTx, ApproveTx, SwapTx] included

// Step 4 – block execution
LendTx:    proposer → attacker: lendAmt KAIA  (SUCCESS, irreversible)
ApproveTx: attacker approves router            (SUCCESS)
SwapTx:    DEX reverts (output < minAmountOut) (REVERT)

// Result
attacker gained: lendAmt KAIA + kept original tokens
proposer lost:   lendAmt KAIA
```

The `checkBalanceForSwap` admission-time guard and the `VerifyExecutable` block-building guard are the two relevant code locations: [6](#0-5) [7](#0-6)

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L107-142)
```go
func (g *GaslessModule) checkBalanceForSwap(swapArgs *SwapArgs, swapNonce uint64) error {
	token := swapArgs.Token
	bc := backends.NewBlockchainContractBackend(g.Chain, nil, nil)

	g.gaslessInfoMu.RLock()
	swapRouter := g.swapRouter
	g.gaslessInfoMu.RUnlock()

	// tx.minAmountOut >= tx.amountRepay
	minAmountOut := swapArgs.MinAmountOut
	amountRepay := swapArgs.AmountRepay
	if minAmountOut.Cmp(amountRepay) < 0 {
		return fmt.Errorf("insufficient minAmountOut: minAmountOut=%s, amountRepay=%s", minAmountOut.String(), amountRepay.String())
	}

	if g.GaslessConfig.ShouldCheckSenderCode() {
		if g.getCurrentHasCode(swapArgs.Sender) {
			return errors.New("sender with code is not allowed")
		}
	}

	if g.GaslessConfig.ShouldCheckSwapAmount() {
		// tx.amountIn >= gsr.getAmountIn(minAmountOut)
		routerContract, err := kip247.NewGaslessSwapRouterCaller(swapRouter, bc)
		if err != nil {
			return err
		}
		// Required token amountIn, given the current exchange rate and the declared minAmountOut.
		requiredAmountIn, err := routerContract.GetAmountIn(nil, token, minAmountOut)
		if err != nil {
			return err
		}
		if swapArgs.AmountIn.Cmp(requiredAmountIn) < 0 {
			return fmt.Errorf("insufficient amountIn: have=%s, want=%s", swapArgs.AmountIn.String(), requiredAmountIn.String())
		}
	}
```

**File:** kaiax/gasless/impl/getter.go (L203-266)
```go
func (g *GaslessModule) IsExecutable(approveTxOrNil, swapTx *types.Transaction) bool {
	err := g.VerifyExecutable(approveTxOrNil, swapTx)
	if err != nil {
		return false
	}
	return true
}

// VerifyExecutable checks if the given transactions form a valid gasless transaction
// It returns an error explaining why the transaction is not executable if it's not,
// and a boolean indicating whether the transaction is executable
func (g *GaslessModule) VerifyExecutable(approveTxOrNil, swapTx *types.Transaction) error {
	// Sx.
	swapArgs, ok := decodeSwapTx(swapTx, g.signer)
	if !ok {
		return ErrDecodeSwapTx
	}
	if !g.isSwapTx(swapArgs) {
		return ErrSwapTxInvalid
	}

	// Conditions involving ApproveTx
	if approveTxOrNil != nil {
		// Ax.
		approveArgs, ok := decodeApproveTx(approveTxOrNil, g.signer)
		if !ok {
			return ErrDecodeApproveTx
		}
		if !g.isApproveTx(approveArgs) {
			return ErrApproveTxInvalid
		}
		// AP1.
		if approveArgs.Sender != swapArgs.Sender {
			return ErrDifferentSenders
		}
		// SP1.
		if approveArgs.Token != swapArgs.Token {
			return fmt.Errorf("%w: approve token %s, swap token %s", ErrDifferentTokens, approveArgs.Token.Hex(), swapArgs.Token.Hex())
		}
		// SP2.
		if approveArgs.Amount.Cmp(swapArgs.AmountIn) < 0 {
			return fmt.Errorf("%w: approve amount %s, required amount %s", ErrInsufficientApproveAmount, approveArgs.Amount.String(), swapArgs.AmountIn.String())
		}
		// SP3.
		if approveTxOrNil.Nonce()+1 != swapTx.Nonce() {
			return fmt.Errorf("%w: approve nonce %d, swap nonce %d (expected %d)", ErrNonSequentialNonce, approveTxOrNil.Nonce(), swapTx.Nonce(), approveTxOrNil.Nonce()+1)
		}
		if nonce := g.getCurrentStateNonce(approveArgs.Sender); nonce != approveTxOrNil.Nonce() {
			return fmt.Errorf("%w: approve nonce %d, current nonce %d", ErrApproveNonceNotCurrent, approveTxOrNil.Nonce(), nonce)
		}
	} else {
		// SP3.
		if nonce := g.getCurrentStateNonce(swapArgs.Sender); nonce != swapTx.Nonce() {
			return fmt.Errorf("%w: swap nonce %d, current nonce %d", ErrSwapNonceNotCurrent, swapTx.Nonce(), nonce)
		}
	}

	// SP4.
	if swapArgs.AmountRepay.Cmp(repayAmount(approveTxOrNil, swapTx)) != 0 {
		return fmt.Errorf("%w: got %s, expected %s", ErrIncorrectRepayAmount, swapArgs.AmountRepay.String(), repayAmount(approveTxOrNil, swapTx).String())
	}

	return nil
}
```

**File:** kaiax/gasless/impl/getter.go (L273-313)
```go
func (g *GaslessModule) GetLendTxGenerator(approveTxOrNil, swapTx *types.Transaction) *builder.TxOrGen {
	var src []byte
	if approveTxOrNil != nil {
		src = append(src, approveTxOrNil.Hash().Bytes()...)
	}
	src = append(src, swapTx.Hash().Bytes()...)
	bundleHash := crypto.Keccak256Hash(src)

	gen := func(nonce uint64) (*types.Transaction, error) {
		var (
			chainId = g.InitOpts.ChainConfig.ChainID
			signer  = types.LatestSignerForChainID(chainId)
			key     = g.InitOpts.NodeKey
		)

		to, err := types.Sender(signer, swapTx)
		if err != nil {
			return nil, err
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeEthereumDynamicFee, map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      nonce,
			types.TxValueKeyTo:         &to,
			types.TxValueKeyAmount:     lendAmount(approveTxOrNil, swapTx),
			types.TxValueKeyData:       common.Hex2Bytes("0x"),
			types.TxValueKeyGasLimit:   params.TxGas,
			types.TxValueKeyGasFeeCap:  swapTx.GasFeeCap(),
			types.TxValueKeyGasTipCap:  swapTx.GasTipCap(),
			types.TxValueKeyAccessList: types.AccessList{},
			types.TxValueKeyChainID:    chainId,
		})
		if err != nil {
			return nil, err
		}

		err = tx.Sign(signer, key)
		return tx, err
	}

	return builder.NewTxOrGenFromGen(gen, bundleHash)
}
```

**File:** kaiax/gasless/impl/getter.go (L346-367)
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
}

func repayAmount(approveTxOrNil, swapTx *types.Transaction) *big.Int {
	// R1 = LendTx.Fee() = SwapTx.GasPrice() * TxGas
	r1 := new(big.Int).Mul(swapTx.GasPrice(), new(big.Int).SetUint64(params.TxGas))

	// RepayAmount = R1 + R2 + R3
	return new(big.Int).Add(r1, lendAmount(approveTxOrNil, swapTx))
}
```

**File:** kaiax/gasless/impl/builder.go (L28-72)
```go
func (g *GaslessModule) ExtractTxBundles(txs []*types.Transaction, prevBundles []*builder.Bundle) []*builder.Bundle {
	// there are only at most two gasless transactions in pending for a sender
	bundles := []*builder.Bundle{}
	approveTxs := map[common.Address]*types.Transaction{}
	targetTxHash := common.Hash{}
	for _, tx := range txs {
		addr, err := types.Sender(g.signer, tx)
		if err != nil {
			continue
		}
		if g.IsApproveTx(tx) {
			approveTxs[addr] = tx
		} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
			bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
			if approveTxs[addr] != nil {
				bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(approveTxs[addr]))
			}
			bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(tx))

			b := builder.NewBundle(
				bundleTxs,
				targetTxHash,
				false,
			)

			targetTxHash = tx.Hash()

			isConflict := false
			for _, prev := range append(prevBundles, bundles...) {
				if prev.IsConflict(b) {
					isConflict = true
					break
				}
			}
			if isConflict {
				// Gasless transactions will just fail even if they aren't bundled.
				continue
			}
			bundles = append(bundles, b)
		} else {
			targetTxHash = tx.Hash()
		}
	}
	return bundles
}
```
