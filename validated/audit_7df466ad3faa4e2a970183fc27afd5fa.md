### Title
Off-by-One Deadline Check Admits Immediately-Expiring Gasless Swap Bundles, Causing Proposer KAIA Loss — (`kaiax/gasless/impl/tx_pool.go`)

---

### Summary

`checkBalanceForSwap` uses a strict-less-than comparison (`< 0`) for the deadline check, meaning a swap transaction with `deadline == currentBlock.Time()` passes txpool admission. Because the next block's timestamp is always strictly greater than the current block's timestamp, the swap contract's `require(block.timestamp <= deadline)` will revert at execution time. The proposer has already irrevocably sent `lendAmount` KAIA to the sender via `lendTx`, and under Kaia's fee-burning model (Magma/Kore), does not recover the full lent amount from gas fees.

---

### Finding Description

The deadline guard in `checkBalanceForSwap` is:

```go
// tx.deadline >= currentTimestamp
deadline := swapArgs.Deadline
if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
    return fmt.Errorf("insufficient deadline: ...")
}
``` [1](#0-0) 

The condition rejects only when `deadline < currentBlock.Time()`. When `deadline == currentBlock.Time()`, `Cmp` returns `0`, which is **not** `< 0`, so the transaction is admitted.

Kaia produces blocks at fixed intervals; the next block's `Time()` is always `> currentBlock.Time()`. Therefore any swap with `deadline == currentBlock.Time()` will be admitted to the txpool but will revert when the swap contract checks `block.timestamp <= deadline`.

There is no deadline re-check during block building. `ExtractTxBundles` calls only `IsExecutable` → `VerifyExecutable`, neither of which inspects the deadline: [2](#0-1) [3](#0-2) 

The bundle `[lendTx, approveTx?, swapTx]` is therefore included in the block. `lendTx` executes successfully (KAIA transferred to sender), `approveTx` executes successfully, and `swapTx` reverts — no `amountRepay` is returned to the proposer.

---

### Impact Explanation

`lendAmount` is defined as:

```go
func lendAmount(approveTxOrNil, swapTx *types.Transaction) *big.Int {
    r := new(big.Int)
    if approveTxOrNil != nil { r.Add(r, approveTxOrNil.Fee()) }
    r.Add(r, swapTx.Fee())
    return r
}
``` [4](#0-3) 

The proposer lends exactly `approveTx.Fee() + swapTx.Fee()` to the sender. Under Kaia's Magma/Kore fee model, **at most half of all block fees reach the proposer** (the other half is burnt), and under low-traffic Kore conditions the proposer receives `max(0, F/2 − gpM)` — potentially zero — from those specific transactions: [5](#0-4) 

Concretely:
- Proposer sends `lendAmount` KAIA to sender: **−lendAmount**
- Proposer collects at most `lendAmount / 2` back as gas fees (Magma NDF), or potentially 0 (Kore DF low-traffic): **+≤ lendAmount/2**
- No `repayAmount` returned (swap reverted): **+0**
- **Net loss per bundle: ≥ lendAmount/2**

The attacker's net cost is zero: they receive `lendAmount` KAIA, spend it on gas, and keep their tokens (swap reverted). The attack is repeatable as long as the attacker holds whitelisted tokens with sufficient approval.

---

### Likelihood Explanation

The attack requires a public RPC call submitting a valid gasless swap transaction (correct token, balance, approval, repayAmount) with `deadline` set to exactly `currentBlock.Time()`. This is a trivially constructable transaction. No privileged access, validator collusion, or key compromise is needed. The attacker bears no net cost.

---

### Recommendation

Change the deadline comparison from `< 0` (greater-than-or-equal) to `<= 0` (strictly-greater-than), so that a deadline equal to the current block time is rejected:

```go
// tx.deadline > currentTimestamp  (must be valid in the NEXT block)
if deadline.Cmp(g.Chain.CurrentBlock().Time()) <= 0 {
    return fmt.Errorf("insufficient deadline: ...")
}
```

Additionally, add a deadline check inside `ExtractTxBundles` or `VerifyExecutable` using the pending block's expected timestamp as a defense-in-depth measure.

---

### Proof of Concept

1. Deploy a whitelisted ERC-20 token; fund attacker with tokens and set approval to `MaxUint256` for the router.
2. Read `currentBlock.Time()` = T.
3. Submit a gasless swap transaction with `deadline = T` (passes `checkBalanceForSwap` because `T.Cmp(T) == 0`, not `< 0`).
4. Mine one block (timestamp = T + blockInterval > T).
5. Observe: `lendTx` succeeds (proposer sends KAIA to attacker), `swapTx` reverts (deadline expired), no `amountRepay` returned.
6. Measure proposer KAIA balance delta: net loss ≥ `lendAmount / 2` due to fee burning.

### Citations

**File:** kaiax/gasless/impl/tx_pool.go (L175-179)
```go
	// tx.deadline >= currentTimestamp
	deadline := swapArgs.Deadline
	if deadline.Cmp(g.Chain.CurrentBlock().Time()) < 0 {
		return fmt.Errorf("insufficient deadline: deadline=%s, want=%s", deadline.String(), g.Chain.CurrentBlock().Time().String())
	}
```

**File:** kaiax/gasless/impl/builder.go (L40-46)
```go
		} else if g.IsSwapTx(tx) && g.IsExecutable(approveTxs[addr], tx) {
			bundleTxs := builder.NewTxOrGenList(g.GetLendTxGenerator(approveTxs[addr], tx))
			if approveTxs[addr] != nil {
				bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(approveTxs[addr]))
			}
			bundleTxs = append(bundleTxs, builder.NewTxOrGenFromTx(tx))

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

**File:** kaiax/reward/README.md (L62-76)
```markdown
- **Magma rule (KIP-71)**: The rule since the Magma hardfork.
  - MR: Same as the previous rule.
  - NDF: Half the fee (F/2) is granted to the proposer. The other half is burnt.
  - DF: Half the fee (F/2) is distributed according to the reward ratio. The other half is burnt.
- **Kore rule (KIP-82)**: The rule since the KIP-82 hardfork.
  - MR: M is distributed according to the reward ratio and KIP-82 ratio.
    - The rewards allocated to stakers is further distributed by their relative staking amounts. The staker rewards are proportional to their staking amounts exceeding the minimum staking amount. The minimum staking amount refers to the `reward.minstake` parameter which determines the staking requirement to be a validator.
    - If no validator has staked more than the minimum staking amount, all staking rewards are sent to the proposer.
    - Remainders from the reward ratio and KIP-82 proposer/staker ratio divisions are sent to Fund1. The remainder from distributing staking rewards among validators is sent to the proposer.
  - NDF: Same as the previous rule.
  - DF: Proposer receives `max(0, F/2 - gpM)` and rest of the fees are burnt.
    - The proposer's minting reward is fixed to a product of minting amount (M), validator's reward ratio (g) and KIP-82 proposer ratio (p). This amount is considered the minimum operation cost of a validator.
    - Among the fees (F), half is always burnt since Magma. The other half (F/2) is burnt up to the proposer's minting reward (gpM), but the exceeding part (F/2 - gpM) is granted to the proposer.
    - Summing up, the proposer is guaranteed a minimum even if transaction fees are no enough to support the validator operating cost, yet incentivized to include as many transactions as possible for more reward.
    - As a special case, if the proposer reward ratio is zero `p=0`, then proposer receives `F/2` and the other `F/2` is burnt.
```
