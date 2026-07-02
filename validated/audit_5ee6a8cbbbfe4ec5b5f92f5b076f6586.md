### Title
Missing Zero-Address Validation in `EVMAddress.deposit()` Allows Permanent Loss of FLOW Tokens - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `EVMAddress` struct in `fvm/evm/stdlib/contract.cdc` accepts any 20-byte array as an EVM address without validating that it is non-zero. The `deposit()` function on `EVMAddress` only checks that the EVM is not paused and that the vault balance is non-zero, but never checks that the destination address is non-zero. Any unprivileged Cadence transaction can construct `EVM.EVMAddress(bytes: [0,0,...,0])` and call `.deposit(from: <-vault)` to permanently send FLOW tokens to the EVM zero address (0x0000...0000), from which they can never be recovered.

---

### Finding Description

The `EVMAddress` struct constructor performs no validation on the provided bytes:

```cadence
view init(bytes: [UInt8; 20]) {
    self.bytes = bytes
}
```

The `deposit()` function checks only for the pause flag and a zero-amount vault, but never validates that `self.bytes` is a non-zero address:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    let amount = from.balance
    if amount == 0.0 {
        destroy from
        return
    }
    let depositedUUID = from.uuid
    InternalEVM.deposit(
        from: <-from,
        to: self.bytes      // <-- no zero-address check
    )
    ...
}
```

This call flows through `newInternalEVMTypeDepositFunction` in `fvm/evm/impl/impl.go`, which calls `AddressBytesArrayValueToEVMAddress` (checking only length, not zero-ness) and then `handler.AccountByAddress(toAddress, false).Deposit(...)`. The EVM state machine accepts a deposit to the zero address without error, crediting the balance to `0x0000000000000000000000000000000000000000`. No private key controls that address, so the tokens are permanently inaccessible.

The `EVMAddress` struct is `access(all)` and its `init` is `view`, making it trivially constructable by any transaction author without any privilege.

---

### Impact Explanation

FLOW tokens deposited to the EVM zero address are permanently lost. The zero address has no controlling key in any EVM-compatible environment. The tokens are credited to that address in the EVM state trie but can never be withdrawn, since `CadenceOwnedAccount.withdraw()` requires an authorized COA resource, and no COA can be created for the zero address. This constitutes an irreversible **cross-VM asset loss** directly analogous to the `recovery == 0` case in the Connext report, where `sendToRecovery()` would send funds to the zero address.

---

### Likelihood Explanation

The entry path is fully reachable by any unprivileged transaction sender. The `EVMAddress` struct is public and its constructor is a `view` function requiring no entitlement. A user who accidentally passes a zero-initialized byte array (e.g., from a bug in a dApp, a misconfigured script, or a malicious contract that tricks a user into depositing to a zero address) will permanently lose their tokens with no on-chain recourse. The pattern `EVM.EVMAddress(bytes: addr).deposit(from: <-vault)` is the standard documented usage for depositing to an arbitrary EVM address, making accidental zero-address deposits a realistic scenario.

---

### Recommendation

Add a pre-condition to `EVMAddress.deposit()` rejecting the zero address:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
        self.bytes != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
            "EVM.EVMAddress.deposit(): Cannot deposit to the zero address"
    }
    ...
}
```

Alternatively, add the check to the `EVMAddress` constructor itself, or to `InternalEVM.deposit` at the Go layer in `newInternalEVMTypeDepositFunction`.

---

### Proof of Concept

Any unprivileged Cadence transaction can execute:

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>

transaction {
    prepare(account: auth(BorrowValue) &Account) {
        let admin = account.storage
            .borrow<&FlowToken.Administrator>(from: /storage/flowTokenAdmin)!
        let minter <- admin.createNewMinter(allowedAmount: 1.0)
        let vault <- minter.mintTokens(amount: 1.0)
        destroy minter

        // Construct the EVM zero address — no validation prevents this
        let zeroAddress = EVM.EVMAddress(
            bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        )
        // 1.0 FLOW is permanently sent to 0x0000...0000 and is unrecoverable
        zeroAddress.deposit(from: <-vault)
    }
}
```

The `EVMAddress` constructor accepts the zero bytes without error. [1](#0-0) 

The `deposit()` function has no zero-address guard and proceeds to call `InternalEVM.deposit`. [2](#0-1) 

The Go-layer `newInternalEVMTypeDepositFunction` validates only address length (20 bytes), not zero-ness, before calling `account.Deposit`. [3](#0-2) 

`AddressBytesArrayValueToEVMAddress` checks only that the byte slice is exactly 20 bytes long. [4](#0-3)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L163-165)
```text
        view init(bytes: [UInt8; 20]) {
            self.bytes = bytes
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L202-223)
```text
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            let amount = from.balance
            if amount == 0.0 {
                destroy from
                return
            }
            let depositedUUID = from.uuid
            InternalEVM.deposit(
                from: <-from,
                to: self.bytes
            )
            emit FLOWTokensDeposited(
                address: self.toString(),
                amount: amount,
                depositedUUID: depositedUUID,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
        }
```

**File:** fvm/evm/impl/impl.go (L277-306)
```go
func AddressBytesArrayValueToEVMAddress(
	context interpreter.ContainerMutationContext,
	addressBytesValue *interpreter.ArrayValue,
) (
	result types.Address,
	err error,
) {
	// Convert

	var bytes []byte
	bytes, err = interpreter.ByteArrayValueToByteSlice(context, addressBytesValue)
	if err != nil {
		return result, err
	}

	// Check length

	length := len(bytes)
	const expectedLength = types.AddressLength
	if length != expectedLength {
		return result, errors.NewDefaultUserError(
			"invalid address length: got %d, expected %d",
			length,
			expectedLength,
		)
	}

	copy(result[:], bytes)

	return result, nil
```

**File:** fvm/evm/impl/impl.go (L660-679)
```go
			toAddressValue, ok := invocation.Arguments[1].(*interpreter.ArrayValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			toAddress, err := AddressBytesArrayValueToEVMAddress(context, toAddressValue)
			if err != nil {
				panic(err)
			}

			// NOTE: We're intentionally not destroying the vault here,
			// because the value of it is supposed to be "kept alive".
			// Destroying would incorrectly be equivalent to a burn and decrease the total supply,
			// and a withdrawal would then have to perform an actual mint of new tokens.

			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))
```
