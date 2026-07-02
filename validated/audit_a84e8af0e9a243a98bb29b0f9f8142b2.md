### Title
`EVM.validateCOAOwnershipProof` Does Not Bind `signedData` to `evmAddress`, Enabling Cross-COA Signature Replay - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` verifies that a Cadence account's keys signed `signedData`, then separately checks that the COA resource at the supplied `path` matches `evmAddress`. However, the function never enforces that `signedData` commits to `evmAddress`. A signature produced to prove ownership of one COA can therefore be replayed by any caller to prove ownership of a *different* COA belonging to the same Cadence account, as long as the attacker supplies the correct `path` for the target COA.

---

### Finding Description

`EVM.validateCOAOwnershipProof` is an `access(all)` Cadence function callable by any script, transaction, or EVM contract (via the Cadence Arch precompile `verifyCOAOwnershipProof`). Its validation logic has two independent steps:

1. Verify that the provided signatures over `signedData` meet the key-weight threshold for the Cadence account at `address`.
2. Borrow the `CadenceOwnedAccount` capability from `path` and compare its EVM address bytes against `evmAddress`. [1](#0-0) 

These two checks are **not linked**: the signature verification is over `signedData`, but `signedData` is never required to encode `evmAddress`. The code itself acknowledges this gap: [2](#0-1) 

Because `EVM.createCadenceOwnedAccount()` can be called multiple times, a single Cadence account can legitimately own several COAs stored at different public paths. When that is the case, a valid `(signedData, signatures)` tuple obtained for COA-A can be submitted with `path = /public/coaB` and `evmAddress = COA-B-address` to pass the proof for COA-B — the signature check passes (same keys, same data) and the address-match check passes (COA-B is indeed at that path).

The precompile entry point `DecodeABIEncodedProof` reads the caller-supplied EVM address directly from ABI-encoded input and passes it unchanged into `COAOwnershipProofInContext.EVMAddress`: [3](#0-2) 

The `coaOwnershipProofValidator` in the handler then forwards this unchecked `EVMAddress` to `validateCOAOwnershipProof`: [4](#0-3) 

---

### Impact Explanation

Any EVM contract or Cadence script can call `verifyCOAOwnershipProof` / `validateCOAOwnershipProof` with an attacker-chosen `(address, path, signedData, keyIndices, signatures, evmAddress)` tuple. If the attacker has observed a valid signature from a victim who owns multiple COAs, the attacker can replay that signature to obtain a `ValidationResult { isValid: true }` for a *different* COA of the same victim. EVM contracts that gate privileged operations on a COA ownership proof (e.g., cross-VM authentication, bridge access controls) would incorrectly accept the replayed proof, granting the attacker the ability to impersonate the victim's ownership of an EVM address they did not authorize for that context.

**Impact: Medium** — false COA ownership proof accepted; attacker can impersonate a victim's control of a specific EVM address in any protocol that relies on `verifyCOAOwnershipProof`.

---

### Likelihood Explanation

**Likelihood: Medium** — the attack requires (a) the victim to own more than one COA under the same Cadence account, and (b) the attacker to have observed a valid signature from the victim. Condition (a) is explicitly supported by the protocol (`EVM.createCadenceOwnedAccount()` is unrestricted). Condition (b) is realistic in any off-chain authentication flow where signatures are broadcast or logged. The function is `access(all)` and reachable from any unprivileged transaction or EVM contract call.

---

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` itself, rather than leaving this as a caller responsibility. Concretely, before verifying signatures, hash or concatenate `evmAddress` into the data that is actually verified:

```cadence
// Bind the proof to the specific EVM address being claimed
let boundData = signedData.concat(evmAddress.toConstantSized<[UInt8; 20]>()!)
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

This ensures a signature produced for COA-A cannot be replayed to prove ownership of COA-B, because the signed payload would differ.

---

### Proof of Concept

1. Alice owns a Cadence account with two COAs:
   - COA-A stored at `/storage/coaA`, capability published at `/public/coaA`
   - COA-B stored at `/storage/coaB`, capability published at `/public/coaB`

2. Alice signs `data = keccak256("login")` with her account key to prove ownership of COA-A for some DeFi protocol. The signature `sig` is broadcast on-chain or observable off-chain.

3. An attacker calls (from any EVM contract via the Cadence Arch precompile):
   ```solidity
   cadenceArch.staticcall(
       abi.encodeWithSignature(
           "verifyCOAOwnershipProof(address,bytes32,bytes)",
           COA_B_address,          // evmAddress = COA-B
           keccak256("login"),     // same signedData
           encodedProof            // proof.Address=Alice, proof.CapabilityPath="/public/coaB",
                                   // proof.KeyIndices=[0], proof.Signatures=[sig]
       )
   );
   ```

4. Inside `validateCOAOwnershipProof`:
   - Signature verification passes: `sig` is valid over `keccak256("login")` for Alice's key.
   - COA address check passes: the capability at `/public/coaB` does resolve to COA-B's EVM address.
   - Returns `ValidationResult { isValid: true }`.

5. The attacker has successfully proven ownership of COA-B using a signature Alice produced for COA-A. [5](#0-4) [6](#0-5)

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

**File:** fvm/evm/precompiles/arch.go (L219-242)
```go
func DecodeABIEncodedProof(input []byte) (*types.COAOwnershipProofInContext, error) {
	index := 0
	caller, err := ReadAddress(input, index)
	index += FixedSizeUnitDataReadSize
	if err != nil {
		return nil, err
	}

	hash, err := ReadBytes32(input, index)
	index += Bytes32DataReadSize
	if err != nil {
		return nil, err
	}

	encodedProof, err := ReadBytes(input, index)
	if err != nil {
		return nil, err
	}

	return types.NewCOAOwnershipProofInContext(
		hash,
		types.Address(caller),
		encodedProof,
	)
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
