The code is fully readable. Let me trace the exact execution path.

The full execution path is now confirmed. Here is the complete analysis:

---

### Title
Allowance Check Bypass in `checkBalanceForSwap` Enables Proposer KAIA Loss via Nonce-Increment Trick — (`kaiax/gasless/impl/tx_pool.go`)

### Summary

`checkBalanceForSwap` skips the ERC20 allowance check when `swapNonce = senderNonce + 1`, assuming an approve tx will precede the swap. However, the check is performed **only at admission time** and is **never re-run at promotion time**. An attacker can exploit this by first incrementing their nonce with a non-approve tx, causing the swap tx to be promoted as a standalone swap with zero allowance. The proposer then lends KAIA for a swap that reverts at execution, losing the lent amount.

### Finding Description

**The bug — `checkBalanceForSwap` (lines 151–163):**

```go
senderNonce := g.getCurrentStateNonce(swapArgs.Sender)
noApproveTxPreceeds := swapNonce == senderNonce   // line 153
if noApproveTxPreceeds {
    // allowance check only runs here
    approval, err := tokenContract.Allowance(...)
    if approval.Cmp(swapArgs.AmountIn) < 0 {
        return fmt.Errorf("insufficient approval: ...")
    }
}
```

When `swapNonce = senderNonce + 1`, `noApproveTxPreceeds` is `false` and the allowance check is entirely skipped. The function returns `nil` (success) even with zero allowance. [1](#0-0) 

**`GetCheckBalance` is called only at admission time** — confirmed by `blockchain/tx_pool.go` lines 920–932, where `checkBalance(tx)` is invoked inside `validateTx` (called once when the tx enters the pool). There is no re-invocation at promotion time. [2](#0-1) 

The `kaiax/interface.go` comment for `GetCheckBalance` explicitly states: *"This is mainly used on checking if module transaction be appended to queue."* [3](#0-2) 

**Promotion path — `isSwapTxReady` (lines 270–290):**

When the sender's state nonce later equals `swapTx.Nonce()` (after a regular tx executes), the swap tx is promoted as a standalone swap (`approveTx = nil`). `IsExecutable(nil, swapTx)` → `VerifyExecutable(nil, swapTx)` only checks nonce equality and repay amount — **no allowance check**. [4](#0-3) [5](#0-4) 

**Block building:** the proposer prepends a lend tx (`[LendTx, SwapTx]`) and lends `swapTx.Fee()` KAIA to the sender. The swap then reverts on-chain due to zero allowance, and the repayment inside the swap contract never executes. [6](#0-5) 

### Impact Explanation

The proposer lends `lendAmount = swapTx.Fee() = swapTx.GasPrice() × swapTx.GasLimit()` KAIA to the attacker. The swap reverts (zero allowance), so the repayment never occurs. The proposer collects only the gas fees for the failed swap execution (which may be less than the gas limit), netting a loss of `lendAmount − gasUsed × gasPrice`. The attacker controls `GasPrice` and `GasLimit` on the swap tx, so the loss can be made arbitrarily large relative to the attacker's cost (a single regular tx at minimum gas). This can be repeated across blocks to continuously drain the proposer.

### Likelihood Explanation

The attacker needs:
1. A small amount of KAIA (to pay for one regular tx at nonce = N, minimum 21,000 gas).
2. Sufficient ERC20 token balance (checked at admission; zero allowance is the attack condition).
3. The regular tx must be mined within `QueueTimeout = 10 seconds` of the swap tx being submitted. [7](#0-6) 

All of these are achievable via public RPC (`eth_sendRawTransaction`). No privileged access, validator collusion, or key compromise is required. Kaia's fast block times make the 10-second window easily satisfiable.

### Recommendation

Re-run the allowance check at promotion time inside `isSwapTxReady` when `approveTx == nil`, or add the allowance check unconditionally in `checkBalanceForSwap` regardless of `noApproveTxPreceeds`. Specifically, when `swapNonce = senderNonce + 1` is admitted to the queue, the allowance must be re-verified at the point of promotion to pending (inside `IsReady`/`isSwapTxReady`) to account for the case where the nonce gap was closed by a non-approve tx.

### Proof of Concept

```
State: sender nonce = 5, ERC20 allowance = 0, token balance >= amountIn

Step 1: Submit regular tx (nonce=5) via eth_sendRawTransaction
        → admitted to pending (attacker pays minimal KAIA for gas)

Step 2: Submit swap tx (nonce=6, amountIn=X, allowance=0) via eth_sendRawTransaction
        → checkBalanceForSwap called:
             senderNonce=5, swapNonce=6
             noApproveTxPreceeds = (6==5) = false
             allowance check SKIPPED
             balance check passes (token balance >= X)
        → swap tx admitted to queue ✓

Step 3: Regular tx (nonce=5) is mined → state nonce becomes 6

Step 4: Pool reset triggers isSwapTxReady for swap tx:
             swapTx.Nonce()=6, stateNonce=6
             → standalone path (approveTx=nil)
             → IsExecutable(nil, swapTx) passes (nonce matches, repay correct)
             → NO allowance check
        → swap tx promoted to pending ✓

Step 5: Block builder creates bundle [LendTx(value=swapTx.Fee()), SwapTx]
        Proposer lends swapTx.Fee() KAIA to sender

Step 6: SwapTx executes → ERC20.transferFrom reverts (allowance=0)
        Repayment never happens → proposer loses lendAmount
```

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L33-35)
```go
	QueueTimeout   = 10 * time.Second // bundle tx is removed from txpool.queue after QueueTimeout
	PendingTimeout = 10 * time.Second // bundle tx is removed from txpool.pending after PendingTimeout
	KnownTxTimeout = 30 * time.Second // bundle tx is removed from knownTxs after KnownTxTimeout
```

**File:** kaiax/gasless/impl/tx_pool.go (L151-163)
```go
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
```

**File:** kaiax/gasless/impl/tx_pool.go (L270-290)
```go
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

**File:** blockchain/tx_pool.go (L918-932)
```go
	// If module recognizes the tx, run an alternative balance check and then skip the default balance check later.
	shouldSkipBalanceCheck := false
	for _, module := range pool.modules {
		if module.IsModuleTx(tx) {
			if checkBalance := module.GetCheckBalance(); checkBalance != nil {
				shouldSkipBalanceCheck = true
				err := checkBalance(tx)
				if err != nil {
					logger.Trace("[tx_pool] invalid funds of module transaction sender", "from", from, "txhash", tx.Hash().Hex())
					return err
				}
			}
			break
		}
	}
```

**File:** kaiax/interface.go (L158-161)
```go
	// Optional actions to check if sender balance is valid for module transaction.
	// This is mainly used on checking if module transaction be appended to queue.
	// If nil is returned, default check (balance > txFee) is performed. Otherwise, the returned function overrides default check.
	GetCheckBalance() func(tx *types.Transaction) error
```

**File:** kaiax/gasless/impl/getter.go (L253-258)
```go
	} else {
		// SP3.
		if nonce := g.getCurrentStateNonce(swapArgs.Sender); nonce != swapTx.Nonce() {
			return fmt.Errorf("%w: swap nonce %d, current nonce %d", ErrSwapNonceNotCurrent, swapTx.Nonce(), nonce)
		}
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
