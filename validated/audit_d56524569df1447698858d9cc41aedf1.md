### Title
Unchecked Arithmetic Overflow in `proofVerifier.ComputeGas` Undercharges EVM Gas for `verifyCOAOwnershipProof` - (File: fvm/evm/precompiles/arch.go)

### Summary
The `ComputeGas` function of the `proofVerifier` EVM precompile computes gas as `ProofVerifierBaseGas + uint64(count)*ProofVerifierGasMultiplerPerSignature`, where `count` is derived from user-supplied ABI-encoded input. This multiplication is unchecked. A sufficiently large `count` causes a `uint64` overflow, wrapping the product to a small value and causing the precompile to report a near-zero gas cost. The EVM then charges the attacker far less gas than the actual work performed, directly analogous to the bootloader `maxFeeThatOperatorCouldTake` overflow described in the external report.

### Finding Description
In `fvm/evm/precompiles/arch.go`, the `ComputeGas` method for the `verifyCOAOwnershipProof` precompile is:

```go
// arch.go line 140
return ProofVerifierBaseGas + uint64(count)*ProofVerifierGasMultiplerPerSignature
```

`ProofVerifierGasMultiplerPerSignature` is `uint64(3_000)`. `count` is extracted from the ABI-encoded `bytes` argument supplied by the EVM transaction sender via `types.COAOwnershipProofSignatureCountFromEncoded(encodedSignature)`. No overflow check is applied before or after the multiplication.

When `uint64(count) > math.MaxUint64 / 3_000` (approximately `6.1 × 10^15`), the product `uint64(count) * 3_000` wraps around modulo `2^64` to a small value. Adding `ProofVerifierBaseGas` (1,000) to this small wrapped value yields a gas cost far below what the actual signature-verification work warrants. The EVM deducts only this small amount from the transaction's gas limit before dispatching to `Run()`. [1](#0-0) 

The constants involved: [2](#0-1) 

### Impact Explanation
The EVM charges gas for a precompile call based solely on the value returned by `RequiredGas` (which delegates to `ComputeGas`). If that value is artificially small due to overflow, the EVM deducts only that small amount from the transaction's gas budget before executing `Run()`. The actual signature-verification work in `Run()` still executes in full. The net effect is that an attacker can trigger arbitrarily many COA ownership proof signature verifications while paying a near-zero EVM gas cost. Because EVM gas maps directly to Flow computation units (and therefore to transaction fees), this constitutes a fee-undercharge: the attacker performs expensive cryptographic work at a fraction of the intended cost.

### Likelihood Explanation
The attack path is fully controlled by an unprivileged EVM transaction sender. The sender constructs a `verifyCOAOwnershipProof` call whose ABI-encoded `bytes` argument encodes a signature count large enough to overflow `uint64` when multiplied by `3_000`. No special privilege, staked node access, or operator cooperation is required. The attacker only needs to submit a valid EVM transaction to the Flow EVM environment.

### Recommendation
Replace the unchecked multiplication with a saturating or overflow-checked variant. For example:

```go
gasForSigs, overflow := bits.Mul64(uint64(count), ProofVerifierGasMultiplerPerSignature)
if overflow != 0 || gasForSigs > math.MaxUint64 - ProofVerifierBaseGas {
    // return a sentinel "too expensive" value or the max uint64
    return math.MaxUint64
}
return ProofVerifierBaseGas + gasForSigs
```

Alternatively, cap `count` at a protocol-defined maximum number of signatures before computing gas. Document the chosen bound and add a test that verifies the overflow case returns a safe value.

### Proof of Concept
1. Craft an ABI-encoded call to `verifyCOAOwnershipProof(address,bytes32,bytes)` where the `bytes` argument encodes a `COAOwnershipProof` whose signature-count field is set to `N = (math.MaxUint64 / 3_000) + 1` (≈ `6.148 × 10^15`).
2. Submit this as an EVM transaction targeting the Cadence Arch precompile address.
3. The EVM calls `RequiredGas` → `ComputeGas`. Inside `ComputeGas`:
   - `count = N`
   - `uint64(N) * 3_000` wraps to a small value `V` (e.g., `3_000` if `N = math.MaxUint64/3_000 + 1`)
   - Return value = `1_000 + V` ≈ `4_000` gas
4. The EVM deducts only `~4_000` gas from the transaction's gas limit.
5. `Run()` executes, attempting to verify `N` signatures — work that should cost `N × 3_000 + 1_000` gas.
6. The attacker has paid `~4_000` gas instead of `~1.8 × 10^19` gas, achieving a near-complete fee bypass for the signature-verification work. [1](#0-0) [3](#0-2)

### Citations

**File:** fvm/evm/precompiles/arch.go (L43-46)
```go
	ProofVerifierBaseGas = uint64(1_000)
	// ProofVerifierGasMultiplerPerSignature is set to match `ECRECOVER`
	// but we might increase this in the future
	ProofVerifierGasMultiplerPerSignature = uint64(3_000)
```

**File:** fvm/evm/precompiles/arch.go (L118-141)
```go
func (f *proofVerifier) ComputeGas(input []byte) uint64 {
	// we compute the gas using a fixed base fee and extra fees
	// per signatures. Note that the input data is already trimmed from the function selector
	// and the remaining is ABI encoded of the inputs

	// skip to the encoded signature part of args (skip address and bytes32 data part)
	index := EncodedAddressSize + Bytes32DataReadSize
	// Reading the encoded signature bytes
	encodedSignature, err := ReadBytes(input, index)
	if err != nil {
		// if any error run would anyway fail, so returning any non-zero value here is fine
		return ProofVerifierBaseGas
	}
	// this method would return the number of signatures from the encoded signature data
	// this saves the extra time needed for full decoding
	// given ComputeGas function is called before charging the gas, we need to keep
	// this function as light as possible
	count, err := types.COAOwnershipProofSignatureCountFromEncoded(encodedSignature)
	if err != nil {
		// if any error run would anyway fail, so returning any non-zero value here is fine
		return ProofVerifierBaseGas
	}
	return ProofVerifierBaseGas + uint64(count)*ProofVerifierGasMultiplerPerSignature
}
```

**File:** fvm/evm/precompiles/arch.go (L143-155)
```go
func (f *proofVerifier) Run(input []byte) ([]byte, error) {
	proof, err := DecodeABIEncodedProof(input)
	if err != nil {
		return nil, err
	}
	verified, err := f.proofVerifier(proof)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, EncodedBoolSize)
	return buffer, EncodeBool(verified, buffer, 0)
}
```
