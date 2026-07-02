### Title
COA Ownership Proof Lacks Chain-Specific Binding, Enabling Cross-Network Signature Replay - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` verifies Flow account signatures over an arbitrary `signedData` byte array using the fixed domain separation tag `"FLOW-V0.0-user"`. This tag is identical across all Flow networks (mainnet, testnet, previewnet, emulator). Because neither the domain tag nor the protocol enforces that `signedData` encodes the target chain ID, a valid COA ownership proof signature produced on one Flow network is cryptographically valid on every other Flow network. Any EVM contract or Cadence script can invoke the proof verifier with a replayed proof.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies a set of Flow account key signatures over caller-supplied `signedData` using a hardcoded, non-chain-specific domain separation tag:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

The function signature is:

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

The protocol places no requirement on the content of `signedData`. The code's own NatSpec comment acknowledges a related replay risk but only for cross-COA replay within the same chain, not cross-network replay:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

The EVM-side entry point is the COA Solidity contract's ERC-1271 implementation, which passes an arbitrary `bytes32 _hash` as `signedData` directly to the `verifyCOAOwnershipProof` Cadence Arch precompile:

```solidity
function isValidSignature(bytes32 _hash, bytes memory _sig)
    external view virtual returns (bytes4) {
    (bool ok, bytes memory data) = cadenceArch.staticcall(
        abi.encodeWithSignature(
            "verifyCOAOwnershipProof(address,bytes32,bytes)",
            address(this), _hash, _sig));
    ...
}
```

The precompile decodes the proof and forwards it to Cadence without adding any chain-specific context:

```go
func DecodeABIEncodedProof(input []byte) (*types.COAOwnershipProofInContext, error) {
    ...
    hash, err := ReadBytes32(input, index)
    ...
    return types.NewCOAOwnershipProofInContext(hash, types.Address(caller), encodedProof)
}
```

Flow account private keys are chain-agnostic (the same key pair is valid on mainnet, testnet, previewnet, and emulator). COA EVM addresses are deterministically derived from the Flow account UUID, so the same Flow account produces the same COA address on every network. Therefore, a signature `sig = Sign("FLOW-V0.0-user" || hash, flowKey)` produced on mainnet is byte-for-byte identical to a valid signature on testnet for the same `hash`.

### Impact Explanation

An attacker who observes a valid COA ownership proof signature on one Flow network (e.g., from an on-chain EVM transaction or emitted event) can replay it on any other Flow network where the same Flow account exists. Any EVM application that uses the COA's ERC-1271 `isValidSignature` for authentication or authorization (e.g., a multisig wallet, a DAO voting contract, a DeFi protocol) will accept the replayed proof as valid. This constitutes unauthorized impersonation of a COA owner across networks, potentially leading to unauthorized asset movement or privilege escalation within EVM applications deployed on multiple Flow networks.

### Likelihood Explanation

- Flow account keys are chain-agnostic by design; the same key pair is used on all networks.
- COA addresses are deterministic, so the same COA address exists on every network for a given Flow account.
- The `verifyCOAOwnershipProof` precompile is callable by any EVM contract without privilege.
- `EVM.validateCOAOwnershipProof` is a public Cadence function callable from any script.
- Signatures are observable on-chain (emitted in EVM transaction events or visible in Cadence transactions).
- Any EVM application deployed on multiple Flow networks (mainnet + testnet is the standard development path) is exposed.

### Recommendation

1. Include the chain ID in the domain separation tag used for COA ownership proof verification, e.g., `"FLOW-V0.0-user-<chainID>"`, making the tag network-specific.
2. Alternatively, enforce at the protocol level that `signedData` must encode the target chain ID and/or the EVM address, and verify this encoding inside `validateCOAOwnershipProof`.
3. Update the `DecodeABIEncodedProof` function in `fvm/evm/precompiles/arch.go` to inject the current chain ID into the proof context so the Cadence verifier can check it.

### Proof of Concept

**Step 1 – On mainnet**, a user signs a hash for an EVM application:
```
sig = Sign("FLOW-V0.0-user" || H, flowAccountKey)
proof = RLP.encode({KeyIndices: [0], Address: flowAccount, CapabilityPath: "coa", Signatures: [sig]})
```

**Step 2 – Attacker observes** the `sig` and `proof` from the mainnet EVM transaction event.

**Step 3 – On testnet**, the attacker submits an EVM transaction calling `isValidSignature(H, proof)` on the COA contract at the same address. The call reaches `verifyCOAOwnershipProof` on the Cadence Arch precompile, which calls `EVM.validateCOAOwnershipProof`. The Cadence function verifies `sig` over `H` with tag `"FLOW-V0.0-user"` — the same tag, the same key, the same hash — and returns `isValid: true`. The testnet EVM application accepts the replayed proof as a valid signature from the COA owner.

---

**Root cause references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** fvm/evm/handler/precompiles.go (L115-153)
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
		if err != nil {
			if types.IsAFatalError(err) {
				panic(err)
			}
			return false, err
		}
		data, ok := value.(cadence.Struct)
		if !ok {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		isValidValue := cadence.SearchFieldByName(data, ValidationResultTypeIsValidFieldName)
		if isValidValue == nil {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		return bool(isValidValue.(cadence.Bool)), nil
	}
}
```
