After tracing the full code path, I can now render a verdict.

**Key facts established:**

1. **`VerifyExecutable` has no deadline check.** It only validates router/token whitelist, sender match, token match, amount sufficiency, nonce ordering, and repay amount. [1](#0-0) 

2. **The deadline check in `checkBalanceForSwap` is unconditional** — it is NOT gated by any `ShouldCheck*` flag and runs at every `BalanceCheckLevel` including `BalanceCheckLevelStatic=0`. [2](#0-1) 

3. **The deadline check compares against `currentBlock.Time()`**, not the next block's timestamp. So `deadline == currentBlock.Time()` passes the check, but the next block's timestamp will be `currentBlock.Time() + blockInterval`, causing the router to revert. [3](#0-2) 

4. **`ExtractTxBundles` calls `IsExecutable` → `VerifyExecutable`** at block-building time, which has no deadline check. A tx with `deadline = currentBlock.Time()` passes this gate and gets bundled. [4](#0-3) 

5. **The lend tx transfers `lendAmount = approveTx.Fee() + swapTx.Fee()` to the user.** If the router reverts (deadline expired), no repayment occurs and the proposer loses this amount. [5](#0-4) 

**The claim about `BalanceCheckLevel=0` bypassing the deadline check is wrong** — the deadline check is unconditional. However, the core vulnerability is real: the deadline is checked against `currentBlock.Time()` at admission, not `nextBlock.Time()`, and `ExtractTxBundles` never re-checks it.

---

### Title
Gasless SwapTx with `deadline == currentBlock.Time()` passes txpool admission but causes router revert at block inclusion, draining proposer's KAIA lend amount — (`kaiax/gasless/impl/getter.go`, `kaiax/gasless/impl/tx_pool.go`)

### Summary
`checkBalanceForSwap` validates `deadline >= currentBlock.Time()` at txpool admission, but `ExtractTxBundles` → `IsExecutable` → `VerifyExecutable` performs no deadline check at block-building time. An attacker can submit a swapTx with `deadline = currentBlock.Time()`, which passes all txpool gates, gets bundled with a proposer-funded lend tx, and then causes the router's `swapForGas` to revert (because `block.timestamp > deadline`). The proposer loses `lendAmount = approveTx.Fee() + swapTx.Fee()` with no repayment.

### Finding Description
The gasless module's two-phase validation has a temporal gap:

- **Txpool admission** (`validateTx` → `GetCheckBalance` → `checkBalanceForSwap`): checks `deadline >= currentBlock.Time()`. A deadline equal to the current block time passes.
- **Block building** (`ExtractTxBundles` → `IsExecutable` → `VerifyExecutable`): no deadline check at all.

Since the next block's timestamp is always `> currentBlock.Time()`, a swapTx with `deadline = currentBlock.Time()` is guaranteed to cause the router's `swapForGas` to revert on execution. The bundle `[LendTx, ApproveTx, SwapTx]` is included, the lend tx transfers KAIA to the user, the approve tx succeeds, and the swap tx reverts — leaving the proposer with no repayment.

The `BalanceCheckLevel` is irrelevant to this attack: the deadline check in `checkBalanceForSwap` is unconditional (outside all `ShouldCheck*` guards), so the attack works at any level. [2](#0-1) [6](#0-5) 

### Impact Explanation
The proposer (block builder) suffers an unauthorized KAIA balance reduction equal to `lendAmount = approveTx.Fee() + swapTx.Fee()` per malicious bundle. This is a direct, unauthorized transfer of KAIA from the proposer's account to the attacker's account (via the lend tx), with no repayment path. This meets the "Unauthorized transfer… affecting KAIA… or system-managed funds" impact gate.

The attack is repeatable: the attacker can submit many such swapTxs (up to `MaxBundleTxsInPending = 100` per pool) to drain the proposer across multiple blocks. [7](#0-6) 

### Likelihood Explanation
The attack requires only a public RPC call to submit a crafted legacy transaction to the gasless router with `deadline = currentBlock.Time()`. No privileged access, governance keys, or validator collusion is needed. The attacker only needs to know the current block timestamp (publicly available) and the whitelisted router/token addresses (readable from chain state). The attack is deterministic and reliable.

### Recommendation
In `ExtractTxBundles` (or in `VerifyExecutable`/`IsExecutable`), add a deadline check against the **next block's expected timestamp** before bundling. At minimum, re-check `swapArgs.Deadline > currentBlock.Time()` (strictly greater, not `>=`) in `ExtractTxBundles` before calling `GetLendTxGenerator`. Ideally, check against `currentBlock.Time() + expectedBlockInterval` to account for the time elapsed between pool admission and block inclusion.

Additionally, the `checkBalanceForSwap` deadline check should use strict inequality (`>` instead of `>=`) to prevent the off-by-one case where `deadline == currentBlock.Time()`.

### Proof of Concept
1. Observe current block time `T = chain.CurrentBlock().Time()`.
2. Craft a valid swapTx (correct router, whitelisted token, valid nonce, correct `amountRepay`) with `deadline = T`.
3. Submit via public RPC (`eth_sendRawTransaction`). The tx passes `checkBalanceForSwap` because `T < T` is false.
4. The tx is promoted to pending and picked up by `ExtractTxBundles`. `IsExecutable` passes (no deadline check).
5. The bundle `[LendTx, SwapTx]` is included in block N+1 with timestamp `T+1`.
6. `swapForGas` in the router checks `require(block.timestamp <= deadline)` → `T+1 <= T` → revert.
7. Proposer's KAIA balance decreases by `lendAmount = swapTx.Fee()` (plus `approveTx.Fee()` if paired) with no repayment.

### Citations

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

**File:** kaiax/gasless/impl/tx_pool.go (L175-179)
```go
	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
	}
```

**File:** kaiax/gasless/impl/builder.go (L40-41)
```go
		} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
			bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
```

**File:** kaiax/gasless/config.go (L80-88)
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
```
