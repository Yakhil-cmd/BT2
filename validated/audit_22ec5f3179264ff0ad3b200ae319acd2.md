### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` Due to Missing EVM Address Binding in Signed Data - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over caller-supplied `signedData`, then separately checks that the COA resource at the given `path` matches the claimed `evmAddress`. Because `signedData` is never required to commit to `evmAddress`, a signature produced to prove ownership of one COA can be replayed verbatim to prove ownership of any other COA controlled by the same Cadence account. The code itself acknowledges this gap in a comment but does not enforce the binding.

---

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` (lines 1011–1116) performs two independent checks:

1. **Signature check** (lines 1082–1093): `keyList.verify(signatureSet: signatureSet, signedData: signedData, domainSeparationTag: "FLOW-V0.0-user")` — verifies that the supplied signatures are cryptographically valid over `signedData` using the Cadence account's keys.

2. **EVM address check** (lines 1095–1110): borrows the COA resource at the caller-supplied `path` and compares its `.address().bytes` against the caller-supplied `evmAddress`. [1](#0-0) 

The two checks are entirely decoupled: the signature commits only to `signedData`, not to `evmAddress` or `path`. An attacker who possesses a valid `(signedData, signatures, keyIndices)` tuple — obtained by observing any prior proof for COA_A — can construct a new call with `path = /public/coa2` and `evmAddress = COA_B_address` (a second COA owned by the same Cadence account). The signature check passes because the same Cadence keys signed the same `signedData`; the EVM address check passes because the COA resource at the new path legitimately holds `COA_B_address`. The function returns `isValid: true` for COA_B without the account owner ever authorizing that proof. [2](#0-1) 

The function is `access(all)` and is callable from any unprivileged Cadence script or transaction. The precompile path (`verifyCOAOwnershipProof` in `fvm/evm/precompiles/arch.go`) is safe because it always passes `address(this)` as `evmAddress`, but the Cadence-level function is exposed directly. [3](#0-2) 

---

### Impact Explanation

Any DApp or protocol that calls `EVM.validateCOAOwnershipProof` directly from Cadence to authenticate a user's control over a specific EVM address is vulnerable. An attacker who intercepts or observes a single valid proof for COA_A can replay it to impersonate the same Cadence account's COA_B. Depending on what the verifying contract or DApp does upon a successful proof (e.g., authorizing withdrawals, granting roles, executing EVM calls on behalf of the proven address), this can result in unauthorized asset movement or privilege escalation on the EVM side.

---

### Likelihood Explanation

The attack requires the victim Cadence account to own at least two COAs at distinct public paths, and requires a DApp to use `validateCOAOwnershipProof` for authentication without binding `signedData` to `evmAddress`. The code comment notes that "Flow wallets historically create at most one COA per account," making this low-probability today. However, the function is `access(all)`, the attack path is fully reachable by an unprivileged sender, and multi-COA accounts are a valid and supported configuration. As COA usage grows, the practical likelihood increases.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` encodes `evmAddress` before performing signature verification, or derive `signedData` internally from `evmAddress` so callers cannot supply an unbound payload. At minimum, the function should reject calls where `signedData` does not contain the 20-byte `evmAddress` as a prefix or suffix, eliminating the cross-COA replay surface without breaking the EVM-side precompile path.

---

### Proof of Concept

**Setup**: Cadence account `X` owns two COAs:
- COA_A stored at `/storage/coa1`, published at `/public/coa1`, EVM address `0xAAAA…`
- COA_B stored at `/storage/coa2`, published at `/public/coa2`, EVM address `0xBBBB…`

**Step 1 – Legitimate proof for COA_A**: A DApp asks account `X` to sign `signedData = "authenticate"` with key index 0. The resulting `(signedData, keyIndices=[0], signatures=[sig])` is submitted to `validateCOAOwnershipProof(address: X, path: /public/coa1, signedData: ..., keyIndices: ..., signatures: ..., evmAddress: 0xAAAA…)` → returns `isValid: true`.

**Step 2 – Replay for COA_B**: Attacker calls `validateCOAOwnershipProof(address: X, path: /public/coa2, signedData: "authenticate", keyIndices: [0], signatures: [sig], evmAddress: 0xBBBB…)`.

- Signature check: `keyList.verify` passes — same key, same `signedData`.
- EVM address check: COA at `/public/coa2` has address `0xBBBB…` — passes.
- Result: `isValid: true` for COA_B, using a signature the owner never produced for COA_B. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1009)
```text
    /// validateCOAOwnershipProof validates a COA ownership proof.
    ///
    /// Note: this function does not enforce that `signedData` includes `evmAddress`.
    /// In principle, a signature produced for one purpose could be replayed here against
    /// a different COA owned by the same Cadence account. In practice this is low-risk:
    /// the EVM-side precompile (verifyCOAOwnershipProof) always passes the calling COA's
    /// address as the evmAddress argument, and Flow wallets historically create at most one
    /// COA per account. Callers building off-chain authentication flows on top of this
    /// function should ensure `signedData` encodes `evmAddress` to prevent cross-address replay.
```

**File:** fvm/evm/stdlib/contract.cdc (L1011-1018)
```text
    fun validateCOAOwnershipProof(
        address: Address,
        path: PublicPath,
        signedData: [UInt8],
        keyIndices: [UInt64],
        signatures: [[UInt8]],
        evmAddress: [UInt8; 20]
    ): ValidationResult {
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1110)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )

        if !isValid{
            return ValidationResult(
                isValid: false,
                problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership for Cadence account \(address). The given signatures are not valid or provide enough weight."
            )
        }

        if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
            // verify evm address matching — capture bytes once to avoid redundant borrow
            let coaAddressBytes = coaRef.address().bytes
            for index, item in coaAddressBytes {
                if item != evmAddress[index] {
                    return ValidationResult(
                        isValid: false,
                        problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. The provided evm address does not match the account's COA address."
                    )
                }
            }
            return ValidationResult(
                isValid: true,
                problem: nil
            )
        }
```

**File:** fvm/evm/handler/precompiles.go (L115-134)
```go
func coaOwnershipProofValidator(contractAddress flow.Address, backend backends.Backend) func(proof *types.COAOwnershipProofInContext) (bool, error) {
	return func(proof *types.COAOwnershipProofInContext) (bool, error) {
		value, err := backend.Invoke(
			environment.ContractFunctionSpec{
				AddressFromChain: func(_ flow.Chain) flow.Address {
					return contractAddress
				},
				LocationName: "EVM",
				FunctionName: "validateCOAOwnershipProof",
				ArgumentTypes: []sema.Type{
					types.FlowAddressSemaType,
					types.PublicPathSemaType,
					types.SignedDataSemaType,
					types.KeyIndicesSemaType,
					types.SignaturesSemaType,
					types.AddressBytesSemaType,
				},
			},
			proof.ToCadenceValues(),
		)
```
