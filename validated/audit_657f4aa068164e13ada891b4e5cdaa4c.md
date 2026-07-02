### Title
Cross-COA ERC1271 Signature Replay via `validateCOAOwnershipProof` Missing Address Binding - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the target `evmAddress`. When a Cadence account owns multiple COAs at different storage paths, a signature produced to prove ownership of one COA can be replayed by an attacker to make `COA_B.isValidSignature()` return `ValidERC1271Signature` for a different COA owned by the same Cadence account.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two independent checks:

1. Verifies that `signatures` over `signedData` are valid for keys of the Cadence account at `address`.
2. Verifies that the COA resource at `path` has an EVM address matching `evmAddress`. [1](#0-0) 

Critically, it never checks that `signedData` encodes `evmAddress`. The two checks are entirely independent. The code itself acknowledges this:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [2](#0-1) [3](#0-2) 

The EVM-side `COA.isValidSignature()` in `coa.sol` calls the Cadence Arch precompile, passing `address(this)` as the EVM address and the caller-supplied `_sig` (an encoded `COAOwnershipProof`) as the proof: [4](#0-3) 

The `COAOwnershipProof` struct contains a `CapabilityPath` field that is fully attacker-controlled: [5](#0-4) 

The precompile decodes the proof and constructs a `COAOwnershipProofInContext` where `EVMAddress` is taken from `address(this)` (the calling COA), while `CapabilityPath` comes from the attacker-supplied encoded proof: [6](#0-5) [7](#0-6) 

### Impact Explanation

An attacker who observes a valid `COAOwnershipProof` for COA_A (signed by a Cadence account that also owns COA_B) can construct a new proof with the same `Address`, `KeyIndices`, and `Signatures`, but with `CapabilityPath` pointing to COA_B's storage path. Calling `COA_B.isValidSignature(_hash, maliciousProof)` will return `ValidERC1271Signature` (`0x1626ba7e`) even though the signer never authorized COA_B for that hash.

Any ERC1271-dependent protocol (ERC-4337 wallet validation, NFT marketplace off-chain orders, EIP-2612 permit-style approvals, DAO voting) that relies on `COA.isValidSignature()` can be deceived into accepting a signature as valid for a COA the signer never intended to authorize.

### Likelihood Explanation

The precondition is a Cadence account that owns two or more COAs at different public paths. This is a supported and documented use case (the `CapabilityPath` field exists precisely to allow multiple COAs per account). The attacker only needs to observe one valid proof (e.g., from a public on-chain transaction or an off-chain authentication flow) and then replay it against a sibling COA. No privileged access is required; `isValidSignature` is an `external view` function callable by any EVM transaction or script.

### Recommendation

Enforce that `signedData` commits to `evmAddress` inside `validateCOAOwnershipProof`. The simplest fix is to require that `signedData` is a hash of `(evmAddress || userMessage)`, or to hash `signedData` together with `evmAddress` before passing it to `keyList.verify()`. This mirrors the EIP-712 fix recommended in the original report: include the verifying contract's address in the signed payload so that a signature for one address cannot be replayed against another.

### Proof of Concept

**Setup**: Cadence account `Alice` owns two COAs:
- COA_A stored at `/storage/coaA`, published at `/public/coaA`, EVM address `0xAAAA`
- COA_B stored at `/storage/coaB`, published at `/public/coaB`, EVM address `0xBBBB`

**Step 1 – Legitimate proof for COA_A**: Alice signs `_hash` with her Cadence key and produces:
```
proofA = COAOwnershipProof{
    Address:        Alice's Cadence address,
    CapabilityPath: "coaA",
    KeyIndices:     [0],
    Signatures:     [sig_over_hash],
}
```

**Step 2 – Attacker constructs replay proof for COA_B**: Attacker copies `proofA` but changes only `CapabilityPath`:
```
proofB = COAOwnershipProof{
    Address:        Alice's Cadence address,
    CapabilityPath: "coaB",   // ← changed
    KeyIndices:     [0],
    Signatures:     [sig_over_hash],  // ← identical
}
```

**Step 3 – Attacker calls `COA_B.isValidSignature(_hash, encode(proofB))`**:

- `coa.sol` line 118 calls `verifyCOAOwnershipProof(address(COA_B), _hash, encode(proofB))`
- Precompile constructs `COAOwnershipProofInContext{EVMAddress: 0xBBBB, SignedData: _hash, ...proofB}`
- `validateCOAOwnershipProof` verifies `sig_over_hash` against Alice's key → **valid** (same key, same hash)
- Checks COA at `/public/coaB` has address `0xBBBB` → **valid**
- Returns `ValidationResult{isValid: true}`
- `isValidSignature` returns `0x1626ba7e` (valid) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** fvm/evm/handler/coa/coa.sol (L114-125)
```text
    function isValidSignature(
        bytes32 _hash,
        bytes memory _sig
    ) external view virtual returns (bytes4){
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
        require(ok);
        bool output = abi.decode(data, (bool));
        if (output) {
            return ValidERC1271Signature;
        }
        return InvalidERC1271Signature;
    }
```

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
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
