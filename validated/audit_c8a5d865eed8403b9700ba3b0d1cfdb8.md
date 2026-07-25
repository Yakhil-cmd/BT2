### Title
Gasless SwapTx Deadline Validated Against Stale Block Time and Not Re-Checked at Bundle-Building Stage, Enabling Proposer KAIA Loss — (`kaiax/gasless/impl/tx_pool.go`, `kaiax/gasless/impl/builder.go`)

---

### Summary

The KIP-247 gasless module enforces the `swapForGas` deadline only once, at txpool admission, and compares it against `g.Chain.CurrentBlock().Time()` — the **last confirmed block's timestamp**, not the timestamp of the block being built. `ExtractTxBundles` and `VerifyExecutable` perform no deadline check at all. A user can craft a `GaslessSwapTx` whose deadline equals the current block time, pass txpool admission, and cause the SwapTx to revert when executed in the next block. Because the proposer has already emitted the `LendTx` (transferring KAIA to the user) as part of the atomic bundle, the proposer loses the lent KAIA without repayment.

---

### Finding Description

**Txpool admission check — wrong reference time**

`checkBalanceForSwap` rejects a SwapTx only when `deadline < currentBlock.Time()`:

```go
// tx.deadline >= currentTimestamp
deadline := swapArgs.Deadline
if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
    return fmt.Errorf("insufficient deadline: ...")
}
``` [1](#0-0) 

`g.Chain.CurrentBlock().Time()` is the timestamp of the **last finalized block**. The block being built will have a strictly higher timestamp (Kaia's block interval is ~1 second). A SwapTx with `deadline == currentBlock.Time()` passes this check but will fail the contract's own `require(block.timestamp <= deadline)` when executed in the next block.

**Block-building stage — no deadline check**

`ExtractTxBundles` calls `IsExecutable` → `VerifyExecutable`. `VerifyExecutable` checks sender identity, token, nonce, and repay amount, but contains **no deadline check**:

```go
func (g *GaslessModule) VerifyExecutable(approveTxOrNil, swapTx *types.Transaction) error {
    // Sx, AP1, SP1, SP2, SP3, SP4 — no deadline check
    ...
    return nil
}
``` [2](#0-1) 

`ExtractTxBundles` itself also performs no deadline check before constructing the bundle:

```go
} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
    bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
    ...
    bundles = append(bundles, b)
}
``` [3](#0-2) 

**Bundle execution order and loss**

The bundle is `[LendTx, ApproveTx?, SwapTx]`. `LendTx` transfers KAIA from the proposer to the user unconditionally. If `SwapTx` subsequently reverts (deadline expired), the proposer's KAIA transfer is not rolled back — it is a separate transaction that already succeeded.

The lend amount is:

```go
func lendAmount(approveTxOrNil, swapTx *types.Transaction) *big.Int {
    r := new(big.Int)
    if approveTxOrNil != nil {
        r.Add(r, approveTxOrNil.Fee())
    }
    r.Add(r, swapTx.Fee())
    return r
}
``` [4](#0-3) 

---

### Impact Explanation

When a SwapTx reverts due to deadline expiry:

1. `LendTx` succeeds — proposer transfers `ApproveTx.Fee() + SwapTx.Fee()` KAIA to the user.
2. `ApproveTx` succeeds — user's ERC-20 approval is set.
3. `SwapTx` reverts — no repayment occurs.

The proposer loses the lent KAIA (R2 + R3). At 50 Gkei gas price with 100k–500k gas limits, this is on the order of 5–25 KAIA per exploited bundle. An attacker can repeat this across multiple blocks by submitting fresh SwapTxs with near-expiry deadlines, draining the proposer's balance incrementally.

---

### Likelihood Explanation

Any unprivileged user can submit a `GaslessSwapTx` with `deadline = currentBlock.Time()`. The txpool check passes (strict less-than comparison). The proposer's `ExtractTxBundles` has no deadline guard and will include the bundle. Kaia's 1-second block interval guarantees the next block's timestamp exceeds the deadline. No special access or validator collusion is required.

---

### Recommendation

1. **Fix the reference time in `checkBalanceForSwap`**: Compare against the expected next block time, e.g., `currentBlock.Time() + expectedBlockInterval`, not the last block's time.

2. **Add a deadline check in `ExtractTxBundles` or `VerifyExecutable`**: Before constructing a bundle, verify `swapArgs.Deadline >= expectedNextBlockTime`. Reject bundles whose deadline will have expired by the time the block is sealed.

```go
// In ExtractTxBundles or VerifyExecutable:
swapArgs, _ := decodeSwapTx(swapTx, g.signer)
nextBlockTime := new(big.Int).Add(g.Chain.CurrentBlock().Time(), big.NewInt(expectedBlockInterval))
if swapArgs.Deadline.Cmp(nextBlockTime) < 0 {
    continue // skip expired bundle
}
```

---

### Proof of Concept

1. Observe `currentBlock.Time()` = `T`.
2. Craft a `GaslessSwapTx` with `deadline = T` (equal to current block time).
3. Submit to txpool. `checkBalanceForSwap` evaluates `T < T` → false → tx admitted.
4. Proposer's `ExtractTxBundles` picks up the bundle (no deadline check). Bundle = `[LendTx, SwapTx]`.
5. `LendTx` executes: proposer sends `SwapTx.Fee()` KAIA to attacker's address. State committed.
6. `SwapTx` executes: `GaslessSwapRouter.swapForGas(...)` checks `require(block.timestamp <= deadline)` → `T+1 <= T` → false → revert.
7. Proposer's KAIA is gone; attacker retains it. Repeat each block.

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L175-179)
```go
	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
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

**File:** kaiax/gasless/impl/getter.go (L346-359)
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
