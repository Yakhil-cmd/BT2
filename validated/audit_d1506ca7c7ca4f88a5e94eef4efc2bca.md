After thorough investigation of the Kaia codebase, I found a valid native analog to the fee-bypass bug in the gasless transaction module (KIP-247).

---

### Title
Proposer KAIA Loss via GaslessSwapTx Revert After LendTx Execution — (`kaiax/gasless/impl/builder.go`, `kaiax/gasless/impl/getter.go`, `kaiax/gasless/impl/tx_pool.go`)

### Summary

The Kaia gasless module (KIP-247) implements a two-phase fee-sponsorship pattern: the block proposer unconditionally lends KAIA to the user via a `LendTx`, then the user's `GaslessSwapTx` is expected to repay the proposer by swapping ERC-20 tokens for KAIA inside `GaslessSwapRouter.swapForGas`. Because `LendTx` and `SwapTx` are **separate, independent transactions**, a revert of `SwapTx` does not roll back `LendTx`. The token-balance and allowance checks that guard admission are performed only at tx-pool time against a stale snapshot; they are **not re-verified at block-building time**. An attacker can arrange for `SwapTx` to revert after `LendTx` has already committed, permanently draining the proposer's node account of the lent KAIA.

### Finding Description

**Phase 1 — Pool admission (stale-snapshot check)**

When a `GaslessSwapTx` is submitted to the tx pool, `GetCheckBalance` is invoked, which calls `checkBalanceForSwap`: [1](#0-0) 

This function checks, against the **current head state**, that:
- `token.balanceOf(sender) >= amountIn`
- `token.allowance(sender, router) >= amountIn` (when no ApproveTx precedes)
- `minAmountOut >= amountRepay`
- `amountIn >= router.getAmountIn(minAmountOut)` (exchange-rate check) [2](#0-1) 

**Phase 2 — Block building (no re-check)**

At block-building time, `ExtractTxBundles` calls `IsExecutable` → `VerifyExecutable`. `VerifyExecutable` only validates static tx fields and nonce ordering; it does **not** re-check token balance, allowance, or the live exchange rate: [3](#0-2) 

If the check passes, `GetLendTxGenerator` unconditionally creates a `LendTx` that transfers `lendAmount` KAIA from the proposer's node key to the user: [4](#0-3) 

where `lendAmount = ApproveTx.Fee() + SwapTx.Fee()`: [5](#0-4) 

The resulting bundle `[LendTx, ApproveTx, SwapTx]` is appended without any guarantee that `SwapTx` will succeed: [6](#0-5) 

**Phase 3 — Execution (LendTx commits, SwapTx reverts)**

`LendTx` is a standard value-transfer transaction. It executes and commits first. `SwapTx` then calls `GaslessSwapRouter.swapForGas`. If `SwapTx` reverts for any reason (token balance drained, allowance revoked, exchange rate moved past `minAmountOut`, fee-on-transfer token, etc.), the EVM rolls back only `SwapTx`'s state changes. `LendTx`'s KAIA transfer is **not** rolled back. The proposer's node account has permanently lost `lendAmount` KAIA.

### Impact Explanation

The block proposer's node account (signing key `g.InitOpts.NodeKey`) loses KAIA equal to:

```
lendAmount = ApproveTx.Fee() + SwapTx.Fee()
           = (ApproveTx.GasLimit × GasPrice) + (SwapTx.GasLimit × GasPrice)
```

Additionally, the proposer pays `LendTx.Fee() = TxGas × SwapTx.GasPrice` for the lend transaction itself. Total proposer loss per failed bundle = `repayAmount`. This is an unauthorized transfer of KAIA from a system-managed fund (the proposer's node account) to the user, matching the allowed-impact gate.

### Likelihood Explanation

Multiple realistic triggers exist, none requiring privileged access:

1. **Approved-spender drain (deliberate):** The user pre-approves a second address they control to spend their tokens. After the gasless txs are admitted to the pool, the second address submits a `transferFrom` that drains the user's token balance. If this tx is included in the same block before the gasless bundle (possible when the proposer does not apply bundle-aware ordering), `SwapTx` reverts.

2. **Exchange-rate shift (market or deliberate):** The pool-admission check verifies `amountIn >= router.getAmountIn(minAmountOut)` at admission time. If the DEX pool's reserves shift between admission and execution (due to other swaps in the same block), the actual swap output falls below `minAmountOut` and `SwapTx` reverts. A colluding searcher can deliberately sandwich the gasless bundle.

3. **Fee-on-transfer / rebasing tokens:** If the whitelisted token deducts a fee on transfer, the router receives less than `amountIn`, causing the swap to produce less than `minAmountOut`.

The `BalanceCheckLevel` flag can be lowered by operators, further weakening the admission-time guards: [7](#0-6) 

### Recommendation

1. **Re-verify token balance and allowance at block-building time** inside `ExtractTxBundles` before generating the `LendTx`, using the pending state after all preceding transactions in the block have been applied.

2. **Make the lend and repayment atomic.** Instead of a standalone `LendTx`, encode the lend as a call into a system contract that holds the KAIA in escrow and releases it to the user only if `swapForGas` succeeds within the same transaction context.

3. **Restrict whitelisted tokens** to those without fee-on-transfer or rebasing behavior, and enforce this at the contract level in `GaslessSwapRouter`.

### Proof of Concept

```
Block N:
  Tx 0 (attacker-controlled, nonce M on address B):
      token.transferFrom(userAddr, attackerAddr, userTokenBalance)
      // drains user's tokens; B was pre-approved by user

  Tx 1 – LendTx (proposer node key, nonce P):
      value = lendAmount KAIA → userAddr
      // COMMITS: proposer loses lendAmount KAIA

  Tx 2 – ApproveTx (userAddr, nonce N):
      token.approve(router, MaxUint256)
      // COMMITS: approval set (but user has 0 tokens)

  Tx 3 – SwapTx (userAddr, nonce N+1):
      router.swapForGas(token, amountIn, minAmountOut, amountRepay, deadline)
      // REVERTS: token.transferFrom(user→router) fails (balance = 0)
      // LendTx is NOT rolled back

Result:
  - userAddr gained lendAmount KAIA (net profit after gas costs)
  - proposer node account lost lendAmount KAIA
  - attackerAddr holds user's original token balance
```

The root cause is the absence of a re-check of live token state between pool admission and block execution, combined with the non-atomic separation of `LendTx` and `SwapTx`.

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L62-72)
```go
func (g *GaslessModule) GetCheckBalance() func(tx *types.Transaction) error {
	return func(tx *types.Transaction) error {
		if approveArgs, ok := decodeApproveTx(tx, g.signer); ok {
			return g.checkBalanceForApprove(approveArgs)
		}
		if swapArgs, ok := decodeSwapTx(tx, g.signer); ok {
			return g.checkBalanceForSwap(swapArgs, tx.Nonce())
		}
		return errors.New("not a gasless transaction") // should not happen because IsModuleTx is called before GetCheckBalance
	}
}
```

**File:** kaiax/gasless/impl/tx_pool.go (L107-182)
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

	if g.GaslessConfig.ShouldCheckToken() {

		tokenContract, err := sc_erc20.NewERC20(token, bc)
		if err != nil {
			return err
		}

		// If SwapTx.nonce is the sender's next nonce, then there is no room for ApproveTx proceeding SwapTx.
		senderNonce := g.getCurrentStateNonce(swapArgs.Sender)
		noApproveTxPreceeds := swapNonce == senderNonce
		if noApproveTxPreceeds {
			// tx.token.allowance(sender, router) >= tx.amountIn
			approval, err := tokenContract.Allowance(nil, swapArgs.Sender, swapRouter)
			if err != nil {
				return err
			}
			if approval.Cmp(swapArgs.AmountIn) < 0 {
				return fmt.Errorf("insufficient approval: approval=%s, want=%s", approval.String(), swapArgs.AmountIn.String())
			}
		}

		// tx.token.balanceOf(sender) >= tx.amountIn
		balance, err := tokenContract.BalanceOf(nil, swapArgs.Sender)
		if err != nil {
			return err
		}
		if balance.Cmp(swapArgs.AmountIn) < 0 {
			return fmt.Errorf("insufficient balance: balance=%s, want=%s", balance.String(), swapArgs.AmountIn.String())
		}
	}

	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
	}

	return nil
}
```

**File:** kaiax/gasless/impl/getter.go (L214-266)
```go
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

**File:** kaiax/gasless/impl/getter.go (L273-312)
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

**File:** kaiax/gasless/impl/builder.go (L40-66)
```go
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
