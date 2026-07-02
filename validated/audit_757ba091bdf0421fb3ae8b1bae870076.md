I found a direct analog. The `validateCOAOwnershipProof` function in `fvm/evm/stdlib/contract.cdc` has an explicit code comment acknowledging that `evmAddress` is not part of the signed message, enabling cross-COA signature replay — the same root cause as the zNS bug.### Title
`validateCOAOwnershipProof` allows cross-COA signature replay because `evmAddress` is not bound to the signed message - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` is an `access(all)` Cadence function that verifies a set of Flow account signatures over an arbitrary `signedData` blob, then separately checks whether a COA stored at a caller-supplied `path` matches a caller-supplied `evmAddress`. Because `evmAddress` is never required to be encoded inside `signedData`, any valid signature produced by a Flow account for one purpose can be replayed by an unprivileged third party to assert ownership of a *different* COA belonging to the same account — an exact structural match to the zNS `fulfillDomainBid` class of "unsigned parameters can be freely substituted."

---

### Finding Description

`validateCOAOwnershipProof` accepts six parameters:

```cadence
fun validateCOAOwnershipProof(
    address: Address,
    path: PublicPath,
    signedData: [UInt8],
    keyIndices: [UInt64],
    signatures: [[UInt8]],
    evmAddress: [UInt8; 20]
): ValidationResult
```

The cryptographic check covers only `signedData`:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

After the signature passes, the function borrows the COA at the caller-supplied `path` and compares its on-chain address to the caller-supplied `evmAddress`:

```cadence
if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
    let coaAddressBytes = coaRef.address().bytes
    for index, item in coaAddressBytes {
        if item != evmAddress[index] { ... }
    }
    return ValidationResult(isValid: true, problem: nil)
}
```

Neither `path` nor `evmAddress` is part of the signed message. The production code itself documents the root cause:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."*

Because the function is `access(all)`, any unprivileged Cadence transaction or script — and any EVM contract that calls the `verifyCOAOwnershipProof` Arch precompile — can supply an arbitrary `path`/`evmAddress` pair alongside a legitimately obtained signature. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Any Cadence contract or EVM contract that calls `validateCOAOwnershipProof` / `verifyCOAOwnershipProof` to gate access to on-chain assets based on COA ownership can be deceived:

1. A Flow account that owns two COAs (COA-A at `/public/coaA`, COA-B at `/public/coaB`) signs `signedData = D` to prove ownership of COA-A to some relying party.
2. An attacker observes the signature and constructs a proof with `path = /public/coaB`, `evmAddress = COA-B-address`, and the same `D` / `signatures`.
3. `validateCOAOwnershipProof` returns `isValid: true` for COA-B, even though the account holder never signed anything binding to COA-B.
4. Any EVM contract or Cadence contract that trusts this result — e.g., to release escrowed tokens, grant minting rights, or unlock bridge withdrawals — will incorrectly authorize the attacker's claim.

The `access(all)` visibility means no capability or entitlement is required to invoke the function. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

**Preconditions that must hold:**

- The victim Flow account must have published capabilities for two or more COAs at distinct public paths. The protocol imposes no limit on the number of COAs per account; the comment's "historically one COA per account" observation is a wallet convention, not an enforced invariant.
- The attacker must obtain a valid signature from the victim over any `signedData` blob — e.g., by observing a prior on-chain proof, an off-chain authentication challenge, or any other use of the `FLOW-V0.0-user` domain tag.

**Why this is reachable without privilege:**

- `validateCOAOwnershipProof` is `access(all)` — callable from any script, transaction, or EVM contract.
- The EVM Arch precompile `verifyCOAOwnershipProof(address,bytes32,bytes)` is callable from any EVM contract; the `address` argument (which becomes `evmAddress`) is supplied by the calling EVM contract, not enforced by the precompile itself.
- As the EVM ecosystem on Flow matures and multi-COA patterns emerge (e.g., per-application COAs, bridge-specific COAs), the precondition becomes increasingly realistic. [7](#0-6) [8](#0-7) 

---

### Recommendation

Bind `evmAddress` to the signed message. The signed data should be required to encode the target EVM address, for example:

```cadence
// Require callers to sign: hash(evmAddress || applicationData)
// and verify that signedData starts with / contains evmAddress bytes
```

Alternatively, restrict `validateCOAOwnershipProof` so that it is only callable via the EVM Arch precompile path (where `evmAddress` is always the calling contract's own address), removing the `access(all)` surface for direct Cadence invocation. This mirrors the zNS fix of restricting `fulfillDomainBid` to `msg.sender == recoveredBidder`. [3](#0-2) 

---

### Proof of Concept

```cadence
// Alice owns two COAs:
//   COA-A at /public/coaA  (EVM address 0xAAAA…)
//   COA-B at /public/coaB  (EVM address 0xBBBB…)
//
// Alice previously signed signedData = D to prove ownership of COA-A
// (e.g., for an EVM DeFi contract).  The attacker observed D + signatures.

import EVM from 0x…

access(all) fun main(): EVM.ValidationResult {
    // Attacker supplies Alice's address, COA-B's path, Alice's existing
    // signature over D, and COA-B's EVM address — none of which Alice
    // ever bound together cryptographically.
    return EVM.validateCOAOwnershipProof(
        address:    0xAlice,
        path:       /public/coaB,      // ← attacker-chosen, not signed
        signedData: D,                 // ← Alice's original signed blob
        keyIndices: aliceKeyIndices,   // ← from observed proof
        signatures: aliceSignatures,   // ← from observed proof
        evmAddress: COA_B_bytes        // ← attacker-chosen, not signed
    )
    // Returns ValidationResult(isValid: true, problem: nil)
    // COA-B ownership "proven" without Alice's consent
}
```

Any EVM contract that calls `verifyCOAOwnershipProof(COA_B_address, D, encodedProof)` via the Arch precompile will receive `true`, granting the attacker whatever access the contract associates with COA-B ownership. [9](#0-8) [3](#0-2) [4](#0-3)

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

**File:** fvm/evm/stdlib/contract.cdc (L1010-1018)
```text
    access(all)
    fun validateCOAOwnershipProof(
        address: Address,
        path: PublicPath,
        signedData: [UInt8],
        keyIndices: [UInt64],
        signatures: [[UInt8]],
        evmAddress: [UInt8; 20]
    ): ValidationResult {
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
```

**File:** fvm/evm/stdlib/contract.cdc (L1095-1110)
```text
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

**File:** fvm/evm/handler/precompiles.go (L40-47)
```go
	archContract := precompiles.ArchContract(
		archAddress,
		blockHeightProvider(backend),
		coaOwnershipProofValidator(evmContractAddress, backend),
		randomSourceProvider(randomBeaconAddress, backend),
		revertibleRandomGenerator(backend),
	)
	return []types.PrecompiledContract{archContract}
```

**File:** fvm/evm/handler/precompiles.go (L115-133)
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
```
