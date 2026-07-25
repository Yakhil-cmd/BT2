### Title
Gasless SwapTx `minAmountOut` Validated Against Stale AMM State at Tx Pool Admission, Not Re-Checked at Block-Building Time, Enabling Block Proposer KAIA Loss — (`kaiax/gasless/impl/tx_pool.go`)

---

### Summary

The KIP-247 gasless module validates the AMM exchange rate (`amountIn >= getAmountIn(minAmountOut)`) only at tx pool admission time inside `checkBalanceForSwap`. At block-building time, `ExtractTxBundles` calls `IsExecutable` → `VerifyExecutable`, which performs only structural checks (nonces, repay amount) and **never re-queries the AMM**. If the AMM price moves between admission and execution — naturally or via a deliberate front-run — the `swapForGas` call reverts, and the block proposer permanently loses the KAIA it lent to the user (R2 + R3 = `ApproveTx.Fee() + SwapTx.Fee()`), with no recovery path.

---

### Finding Description

**Admission-time check (tx pool):**

`checkBalanceForSwap` in `kaiax/gasless/impl/tx_pool.go` enforces:

```
tx.minAmountOut >= tx.amountRepay
tx.amountIn    >= gsr.getAmountIn(minAmountOut)   // AMM query at current head
``` [1](#0-0) 

The AMM query (`routerContract.GetAmountIn`) reads the live pool reserves at the block head when the tx enters the pool. This snapshot is never refreshed.

**Block-building time (no re-check):**

`ExtractTxBundles` in `kaiax/gasless/impl/builder.go` calls `IsExecutable` → `VerifyExecutable` for every candidate bundle: [2](#0-1) 

`VerifyExecutable` only checks structural invariants (sender match, token match, approve amount, nonce sequence, exact `amountRepay`). It contains **no AMM state query**: [3](#0-2) 

**Lend transaction is unconditional:**

Once `IsExecutable` returns `true`, `GetLendTxGenerator` is called and the proposer's KAIA is transferred to the user: [4](#0-3) 

The lend amount is `R2 + R3 = ApproveTx.Fee() + SwapTx.Fee()`: [5](#0-4) 

**Gap:** Between the moment the tx is admitted to the pool and the moment the block is built, any swap against the same AMM pair can shift the reserves enough that `amountIn < getAmountIn(minAmountOut)` at execution time. The `swapForGas` call in the `GaslessSwapRouter` contract will then revert (the AMM's `swapExactTokensForTokens` enforces `minAmountOut` on-chain). The LendTx has already executed and transferred KAIA to the user; the revert of `swapForGas` does not roll back the LendTx because they are separate transactions in the bundle.

---

### Impact Explanation

The block proposer's KAIA balance decreases by `ApproveTx.Fee() + SwapTx.Fee()` per failed bundle. An adversary who can observe the mempool can deliberately front-run the gasless bundle with a large swap that moves the AMM price past the user's `minAmountOut` threshold, causing the swap to revert while the lend is already settled. The proposer receives no repayment. Repeated across many gasless bundles, this drains the proposer's KAIA balance. This constitutes an unauthorized transfer of KAIA from the proposer's account with no compensation.

---

### Likelihood Explanation

- The gasless module is enabled by default (`Disable: false`) and the swap-amount check is enabled at the default `BalanceCheckLevelAll`.
- AMM prices change every block due to normal trading activity; even without a deliberate attacker, a tx that sat in the queue for one or two blocks can fail if the pool moved.
- A deliberate attacker needs only to submit one large swap against the same pair in the same or a preceding block — no privileged access required.
- The `BalanceCheckLevel` is operator-configurable; if set to `BalanceCheckLevelStatic` (0) or `BalanceCheckLevelTokenBalanceAndAllowance` (1), the AMM check is skipped entirely at admission, making the window even wider. [6](#0-5) 

---

### Recommendation

Re-validate the AMM exchange rate inside `ExtractTxBundles` (or inside `IsExecutable` when called from the builder) before committing to create the LendTx. Specifically, call `routerContract.GetAmountIn(nil, token, minAmountOut)` against the current chain head and verify `swapArgs.AmountIn >= requiredAmountIn` before appending the bundle. This mirrors the admission-time check and closes the stale-price window.

---

### Proof of Concept

1. AMM pool for `TOKEN/WKAIA` has reserves such that `getAmountIn(minAmountOut) = Y` at block N.
2. User submits `SwapTx` with `amountIn = Y`, `minAmountOut = X` (where `X >= amountRepay`). `checkBalanceForSwap` passes at block N.
3. At block N, another trader submits a large `TOKEN → WKAIA` swap that depletes WKAIA reserves. `getAmountIn(X)` is now `Y' > Y`.
4. At block N+1, the proposer calls `ExtractTxBundles`. `IsExecutable` → `VerifyExecutable` passes (no AMM check). The proposer generates `LendTx` and includes the bundle `[LendTx, ApproveTx, SwapTx]`.
5. `LendTx` executes: proposer transfers `ApproveTx.Fee() + SwapTx.Fee()` KAIA to the user. ✓
6. `ApproveTx` executes: user approves `amountIn = Y` tokens to the router. ✓
7. `SwapTx` executes: `GaslessSwapRouter.swapForGas` calls the underlying AMM with `amountIn = Y` and `minAmountOut = X`. The AMM can only produce `X' < X` KAIA for `Y` tokens (reserves shifted). The call reverts.
8. The revert of `SwapTx` does **not** roll back `LendTx`. The proposer has lost `ApproveTx.Fee() + SwapTx.Fee()` KAIA with no repayment. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** kaiax/gasless/impl/builder.go (L28-71)
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
```

**File:** kaiax/gasless/impl/getter.go (L211-266)
```go
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

**File:** kaiax/gasless/config.go (L64-100)
```go
const (
	BalanceCheckLevelStatic                   = iota // relation between amounts and deadline
	BalanceCheckLevelTokenBalanceAndAllowance        // all above + token balance and allowance
	BalanceCheckLevelSwapAmount                      // all above +	amountIn calculated by dex
	BalanceCheckLevelAll                             // all above +	sender code check
)

type GaslessConfig struct {
	// all tokens are allowed if AllowedTokens is nil while all are disallowed if empty slice
	AllowedTokens         []common.Address `toml:",omitempty"`
	Disable               bool
	MaxBundleTxsInPending uint
	MaxBundleTxsInQueue   uint
	BalanceCheckLevel     int
}

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

func (cfg *GaslessConfig) ShouldCheckSenderCode() bool {
	return cfg.BalanceCheckLevel >= BalanceCheckLevelAll
}
```
