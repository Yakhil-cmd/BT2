### Title
Stale `currentBlock.Time()` in `checkBalanceForSwap` Deadline Gate Allows Proposer KAIA Loss via Expired Gasless Swap — (File: `kaiax/gasless/impl/tx_pool.go`)

---

### Summary

The gasless-swap txpool admission check validates the user-supplied `deadline` against `g.Chain.CurrentBlock().Time()` — the **last finalized** block's timestamp. Because Kaia enforces `nextBlock.Time >= parentBlock.Time + BlockGenerationInterval`, the next block's timestamp is strictly greater than the current block's timestamp. A user can therefore craft a `GaslessSwapTx` with `deadline == currentBlock.Time()`, which passes the txpool gate but will fail the on-chain `require(block.timestamp <= deadline)` check inside `GaslessSwapRouter.swapForGas()`. The proposer's `LendTx` — which transfers KAIA to the user — executes unconditionally before the `SwapTx`. When `SwapTx` reverts, the proposer's lent KAIA is never repaid, resulting in a direct, unauthorized loss of KAIA from the proposer.

---

### Finding Description

In `kaiax/gasless/impl/tx_pool.go`, `checkBalanceForSwap` performs the following deadline gate:

```go
// tx.deadline >= currentTimestamp
deadline := swapArgs.Deadline
if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
    return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", ...)
}
``` [1](#0-0) 

The reference value is `g.Chain.CurrentBlock().Time()` — the timestamp of the **already-sealed** head block. The block in which the bundle will actually execute has a timestamp that is at minimum `currentBlock.Time() + BlockGenerationInterval` seconds later, as enforced by the block validator:

```go
if parent.Time.Uint64()+uint64(params.BlockGenerationInterval) > header.Time.Uint64() {
    return ErrInvalidTimestamp
}
``` [2](#0-1) 

This creates a window `[currentBlock.Time(), nextBlock.Time() - 1]` where a deadline value passes the txpool check but is already expired at execution time.

Neither `isReady` / `isSwapTxReady` nor `IsExecutable` / `VerifyExecutable` re-validate the deadline before the bundle is promoted or built: [3](#0-2) [4](#0-3) 

The gasless bundle execution order is `[LendTx → ApproveTx → SwapTx]`: [5](#0-4) 

`LendTx` is a plain value-transfer signed by the proposer's node key that sends KAIA to the user: [6](#0-5) 

Each transaction in the bundle is independent. If `SwapTx` reverts (due to the on-chain deadline check inside `GaslessSwapRouter.swapForGas`), the state changes from `LendTx` are **not** rolled back. The proposer has already transferred KAIA to the user with no repayment.

The `swapForGas` function signature confirms the `deadline` parameter is forwarded to the contract: [7](#0-6) 

---

### Impact Explanation

**Impact: Medium**

The proposer (a privileged block-building node) suffers an unauthorized loss of KAIA. The lent amount equals `swapTx.Fee() + approveTx.Fee()` (gas limit × gas price for each tx). With typical parameters (swap gasLimit ≈ 1 000 000, gasPrice ≈ 50 Gkei), each attack drains ≈ 0.05 KAIA from the proposer. An attacker controlling multiple EOAs can repeat this across different accounts, bypassing the per-tx `KnownTxTimeout = 30s` guard, to drain the proposer's balance continuously.

The corrupted value is the proposer's KAIA balance: `lendAmount` is debited from the proposer and credited to the attacker with no offsetting repayment.

---

### Likelihood Explanation

**Likelihood: Medium**

The current block timestamp is public. Any user holding a whitelisted ERC-20 token (required to pass `checkBalanceForSwap`'s balance/allowance checks) can trivially set `deadline = currentBlock.Time()`. No privileged access, no majority-validator collusion, and no external service is required. The only prerequisite is holding the token, which is the normal precondition for using the gasless feature.

---

### Recommendation

Replace the deadline reference in `checkBalanceForSwap` with the **minimum possible next-block timestamp**:

```go
// Use next block's minimum timestamp, not the already-sealed head
nextBlockMinTime := new(big.Int).Add(
    g.Chain.CurrentBlock().Time(),
    new(big.Int).SetUint64(uint64(params.BlockGenerationInterval)),
)
if deadline.Cmp(nextBlockMinTime) < 0 {
    return fmt.Errorf("insufficient deadline: deadline=%s, want>=%s",
        deadline.String(), nextBlockMinTime.String())
}
```

Additionally, re-validate the deadline inside `ExtractTxBundles` (or `IsExecutable`) at bundle-build time, so that a swap tx whose deadline has since expired is silently dropped rather than bundled with a live `LendTx`.

---

### Proof of Concept

1. Attacker holds whitelisted token `T` and observes `currentBlock.Time() = T_now`.
2. Attacker submits `ApproveTx` (approve router for `MaxUint256` of token `T`) and `SwapTx` with `deadline = T_now`.
3. `checkBalanceForSwap` evaluates `T_now >= T_now` → **passes**; both txs enter the pool.
4. Proposer's `ExtractTxBundles` detects the pair, calls `GetLendTxGenerator`, and builds bundle `[LendTx, ApproveTx, SwapTx]`.
5. Block is sealed with timestamp `T_now + BlockGenerationInterval` (≥ `T_now + 1`).
6. `LendTx` executes: proposer transfers `lendAmount` KAIA to attacker. ✓
7. `ApproveTx` executes: attacker approves router. ✓
8. `SwapTx` executes: `GaslessSwapRouter.swapForGas()` checks `require(block.timestamp <= deadline)` → `T_now + interval > T_now` → **reverts**.
9. Attacker retains `lendAmount − gas_consumed` KAIA; proposer is not repaid.
10. Attacker repeats with a fresh EOA (bypassing `KnownTxTimeout`).

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L175-179)
```go
	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
	}
```

**File:** kaiax/gasless/impl/tx_pool.go (L269-290)
```go
// isSwapTxReady assumes that the caller checked `g.IsSwapTx(swapTx)`
func (g *GaslessModule) isSwapTxReady(swapTx, prevTx *types.Transaction) bool {
	addr, err := types.Sender(g.signer, swapTx)
	if err != nil {
		return false
	}
	nonce := g.getCurrentStateNonce(addr)

	var approveTx *types.Transaction
	if swapTx.Nonce() == nonce {
		approveTx = nil
	} else if swapTx.Nonce() == nonce+1 {
		if prevTx == nil || !g.IsApproveTx(prevTx) {
			return false
		}
		approveTx = prevTx
	} else {
		return false
	}

	return g.IsExecutable(approveTx, swapTx)
}
```

**File:** blockchain/block_validator.go (L168-170)
```go
	if parent.Time.Uint64()+uint64(params.BlockGenerationInterval) > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}
```

**File:** kaiax/gasless/impl/getter.go (L40-41)
```go
	// function swapForGas(address token, uint256 amountIn, uint256 minAmountOut, uint256 amountRepay, uint256 deadline) external
	routerAbiJson = `[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"minAmountOut","type":"uint256"},{"internalType":"uint256","name":"amountRepay","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapForGas","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
```

**File:** kaiax/gasless/impl/getter.go (L211-265)
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
```

**File:** kaiax/gasless/impl/getter.go (L293-310)
```go
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
