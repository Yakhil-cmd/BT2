### Title
Gasless Swap Deadline Off-by-One Allows Proposer to Lend Gas for Inevitably-Reverting Bundles — (`kaiax/gasless/impl/tx_pool.go`)

### Summary

The txpool deadline guard in `checkBalanceForSwap` uses a strict-less-than comparison (`< 0`) that accepts swap transactions whose `deadline` equals the current block's timestamp. Because every subsequent block carries a strictly higher timestamp, such transactions are guaranteed to revert inside `GaslessSwapRouter.swapForGas` at execution time. The proposer has already transferred the lend amount (KAIA) to the user via the prepended `LendTx`; the failed `SwapTx` never repays it, so the proposer loses real KAIA with no recourse.

### Finding Description

`checkBalanceForSwap` enforces the deadline with:

```go
// tx.deadline >= currentTimestamp
deadline := swapArgs.Deadline
if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
    return fmt.Errorf("insufficient deadline: ...")
}
``` [1](#0-0) 

`deadline.Cmp(currentBlock.Time()) < 0` is true only when `deadline < currentBlock.Time()`. When `deadline == currentBlock.Time()` the comparison returns `0`, the condition is **false**, and the transaction is admitted to the pool.

Kaia produces one block per second; the next block's `block.timestamp` is at minimum `currentBlock.Time() + 1`. Therefore any swap transaction with `deadline == currentBlock.Time()` will be included in a bundle by the proposer but will revert on-chain when the Uniswap-compatible router inside `GaslessSwapRouter` checks `require(deadline >= block.timestamp)`.

The block-building path (`ExtractTxBundles` → `IsExecutable` → `VerifyExecutable`) performs no deadline check at all:

```go
} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
    bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
``` [2](#0-1) 

`VerifyExecutable` checks sender, token, nonce, and repay amount — but never `deadline`: [3](#0-2) 

The lend amount transferred to the user is `ApproveTx.Fee() + SwapTx.Fee()`: [4](#0-3) 

When `SwapTx` reverts, this KAIA is never returned to the proposer.

### Impact Explanation

A user who sets `deadline = currentBlock.Time()` causes the proposer to:
1. Execute `LendTx` — transferring `lendAmount` KAIA to the user.
2. Execute `SwapTx` — which reverts because `block.timestamp > deadline` in the new block.

The proposer's KAIA balance is permanently reduced by `lendAmount` per exploited bundle. The attack is repeatable: the attacker can submit a new crafted swap transaction every block, draining the proposer's balance at a rate bounded only by the gas price and the `MaxBundleTxsInPending` limit.

### Likelihood Explanation

The attacker only needs to:
- Query `eth_getBlockByNumber("latest")` to read `currentBlock.Time()`.
- Construct a syntactically valid `swapForGas` calldata with `deadline = currentBlock.Time()`.
- Submit the transaction to any node.

No special privilege, validator access, or key compromise is required. The attack is fully automatable.

### Recommendation

Change the comparison from strict-less-than to less-than-or-equal so that transactions whose deadline has already reached the current block time are also rejected:

```go
// tx.deadline > currentTimestamp  (must survive at least one more block)
if deadline.Cmp(g.Chain.CurrentBlock().Time()) <= 0 {
    return fmt.Errorf("insufficient deadline: deadline=%s, want>%s",
        deadline.String(), g.Chain.CurrentBlock().Time().String())
}
``` [1](#0-0) 

Additionally, add a deadline check inside `VerifyExecutable` / `ExtractTxBundles` so that bundles whose deadline has expired between pool admission and block building are also dropped before the `LendTx` is generated.

### Proof of Concept

1. Read `T = eth_getBlockByNumber("latest").timestamp`.
2. Build a legacy transaction to `GaslessSwapRouter` calling `swapForGas(token, amountIn, minAmountOut, amountRepay, T)` with valid token/amount fields that satisfy all other `checkBalanceForSwap` conditions.
3. Submit the transaction. The txpool check passes because `T.Cmp(T) == 0`, which is not `< 0`.
4. The proposer's node promotes the swap, prepends a `LendTx` transferring `lendAmount` KAIA to the attacker, and seals the block.
5. During execution, `GaslessSwapRouter.swapForGas` calls the Uniswap router with `deadline = T`; the router reverts because `block.timestamp = T+1 > T`.
6. `SwapTx` reverts; `LendTx` is already committed. The proposer's balance is reduced by `lendAmount` KAIA; the attacker retains it.

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L175-179)
```go
	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
	}
```

**File:** kaiax/gasless/impl/builder.go (L40-45)
```go
		} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
			bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
			if approveTxs[addr] != nil {
				bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(approveTxs[addr]))
			}
			bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(tx))
```

**File:** kaiax/gasless/impl/getter.go (L214-265)
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
