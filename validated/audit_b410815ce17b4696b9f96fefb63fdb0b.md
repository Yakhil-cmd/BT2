### Title
`EVM.mustRun()` Silently Passes `Status.failed` Without Reverting, Enabling Cross-VM Asset Loss — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.mustRun()` in `fvm/evm/stdlib/contract.cdc` carries a name that strongly implies success-or-revert semantics, but its `assert` only guards against `Status.unknown` (invalid/unexecuted transactions). A `Status.failed` result — meaning the EVM transaction was executed but reverted — passes through silently without rolling back the enclosing Cadence transaction. The critical caveat is buried in a single comment line that a Cadence contract author can easily overlook, directly mirroring the external report's pattern of a critical warning hidden in unformatted text before an irreversible action.

---

### Finding Description

`EVM.mustRun()` is declared `access(all)` and is callable by any unprivileged Cadence transaction or contract author:

```cadence
/// mustRun runs the transaction using EVM.run
/// It will rollback if the tx execution status is unknown or invalid.
/// Note that this method does not rollback if transaction
/// is executed but an vm error is reported as the outcome
/// of the execution (status: failed).
access(all)
fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.failed || runResult.status == Status.successful,
        message: "EVM.mustRun(): The provided transaction is not valid for execution"
    )
    return runResult
}
```

The `assert` condition is:

```
runResult.status == Status.failed || runResult.status == Status.successful
```

This evaluates to `true` for **both** a successful and a failed EVM execution. The Cadence `assert` only panics when the status is `Status.unknown` (i.e., the transaction was rejected before execution). A `Status.failed` result — where the EVM transaction ran but reverted — satisfies the condition and the Cadence transaction continues to commit.

The three EVM result statuses are:

| Status | Meaning |
|---|---|
| `StatusUnknown` (0) | Transaction rejected, not executed |
| `StatusFailed` (2) | Transaction executed, VM returned error |
| `StatusSuccessful` (3) | Transaction executed, no error |

The function name `mustRun` is the only signal a contract author sees at the call site. The critical caveat — that `Status.failed` does not cause a revert — is a single comment line that is easy to miss, especially when the function is imported and used across contract boundaries.

---

### Impact Explanation

A Cadence contract author who uses `mustRun()` as a "safe" wrapper that guarantees atomicity between a Cadence-side irreversible action and an EVM-side action will produce contracts with the following failure mode:

1. The contract destroys a Cadence resource (NFT, FT vault) or burns tokens — an irreversible action within the transaction.
2. The contract calls `EVM.mustRun()` expecting the Cadence transaction to revert if the EVM side fails.
3. The EVM transaction fails (`Status.failed`) — e.g., the target EVM contract reverts, runs out of gas, or the EVM state is inconsistent.
4. `mustRun()` does **not** revert the Cadence transaction.
5. The Cadence transaction commits: the resource is permanently destroyed and no corresponding EVM action occurred.
6. The on-chain asset is permanently lost with no recovery path.

This is a cross-VM asset loss: the Cadence side commits an irreversible destruction while the EVM side reverts, leaving the total supply of the asset permanently reduced.

---

### Likelihood Explanation

**Medium.** `EVM.mustRun()` is `access(all)` and is the natural choice for any contract author who wants a "stricter" version of `EVM.run()`. The name `mustRun` is the only signal at the call site; the critical caveat is only in a comment. Any Cadence contract that:

- Uses `mustRun()` to coordinate a Cadence-side destruction with an EVM-side mint or transfer, and
- Does not explicitly check `result.status == Status.successful` after the call,

is vulnerable. This pattern is especially likely in bridge-adjacent contracts, NFT migration contracts, or any contract implementing a "burn-and-mint" cross-VM flow.

---

### Recommendation

**Short term:** Rename `mustRun()` to a name that does not imply success, such as `runOrRevertOnInvalid()`, and add a prominent, multi-line warning at the top of the doc comment — not buried after the description — that `Status.failed` does not cause a revert.

**Long term:** Introduce a separate `mustRunSuccessful()` function that asserts `runResult.status == Status.successful`, providing true success-or-revert semantics. This gives contract authors a safe primitive that matches the mental model the current name implies.

---

### Proof of Concept

The following Cadence transaction demonstrates the failure mode. The NFT is permanently destroyed even though the EVM transaction fails:

```cadence
import EVM from <EVM_ADDRESS>
import NonFungibleToken from <NFT_ADDRESS>

// A contract author writes this, believing mustRun() will revert if EVM fails.
transaction(failingEvmTxBytes: [UInt8]) {
    prepare(signer: auth(Storage) &Account) {
        // Step 1: Irreversible Cadence action — destroy the NFT.
        let nft <- signer.storage.load<@{NonFungibleToken.NFT}>(
            from: /storage/myNFT
        ) ?? panic("no NFT")
        destroy nft   // permanently destroyed; cannot be recovered

        // Step 2: Call mustRun() expecting atomicity.
        // If the EVM tx fails (Status.failed), the author expects a revert.
        // But mustRun() does NOT revert on Status.failed.
        let coinbase = EVM.EVMAddress(bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
        let result = EVM.mustRun(tx: failingEvmTxBytes, coinbase: coinbase)

        // result.status == Status.failed (2), assert passed, transaction commits.
        // The NFT is gone. No EVM token was minted. Asset is permanently lost.
    }
}
```

The root cause is confirmed at: [1](#0-0) 

The `Status` values that make `Status.failed` pass the assert silently: [2](#0-1) 

The `EVM.run()` function that `mustRun()` delegates to, which does not revert on EVM failure: [3](#0-2)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L827-836)
```text
    access(all)
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.run(
            tx: tx,
            coinbase: coinbase.bytes
        ) as! Result
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L838-851)
```text
    /// mustRun runs the transaction using EVM.run
    /// It will rollback if the tx execution status is unknown or invalid.
    /// Note that this method does not rollback if transaction
    /// is executed but an vm error is reported as the outcome
    /// of the execution (status: failed).
    access(all)
    fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
        let runResult = self.run(tx: tx, coinbase: coinbase)
        assert(
            runResult.status == Status.failed || runResult.status == Status.successful,
            message: "EVM.mustRun(): The provided transaction is not valid for execution"
        )
        return runResult
    }
```

**File:** fvm/evm/types/result.go (L30-42)
```go
var (
	StatusUnknown Status = 0
	// StatusInvalid shows that the transaction was not a valid
	// transaction and rejected to be executed and included in any block.
	StatusInvalid Status = 1
	// StatusFailed shows that the transaction has been executed,
	// but the output of the execution was an error
	// for this case a block is formed and receipts are available
	StatusFailed Status = 2
	// StatusSuccessful shows that the transaction has been executed and the execution has returned success
	// for this case a block is formed and receipts are available
	StatusSuccessful Status = 3
)
```
