### Title
`validateCOAOwnershipProof` Allows Signature Reuse Across Networks and Contexts — (`fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies Flow account key signatures over an arbitrary caller-supplied `signedData` blob using the hardcoded domain separation tag `"FLOW-V0.0-user"`. Because neither the network/chain identity nor the target EVM address is enforced to be part of the signed payload, a valid signature produced on one Flow network (or for any other purpose sharing the same tag) can be replayed on a different network or against a different COA, bypassing the COA ownership authentication schema.

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies that a set of Flow account keys signed over `signedData` using the domain separation tag `"FLOW-V0.0-user"`:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
``` [1](#0-0) 

The `signedData` is an opaque byte array supplied entirely by the caller — the function imposes no constraint that it encodes the target `evmAddress`, the network ID, or any other context-binding value. The code itself acknowledges the cross-address replay risk in a comment but dismisses it:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [2](#0-1) 

The comment does not address cross-network replay. The tag `"FLOW-V0.0-user"` is a generic user-signing tag with no network or deployment binding. It is distinct from the transaction tag (`"FLOW-V0.0-transaction"`) but is shared across all Flow networks (Mainnet, Testnet, any fork). [3](#0-2) 

The primary on-chain entry point is the ERC-1271 `isValidSignature` function in the COA Solidity contract, which calls the Cadence Arch precompile `verifyCOAOwnershipProof(address, bytes32, bytes)`:

```solidity
(bool ok, bytes memory data) = cadenceArch.staticcall(
    abi.encodeWithSignature(
        "verifyCOAOwnershipProof(address,bytes32,bytes)",
        address(this), _hash, _sig
    )
);
``` [4](#0-3) 

The precompile decodes the proof and delegates to `coaOwnershipProofValidator`, which calls `validateCOAOwnershipProof` in the EVM Cadence contract: [5](#0-4) 

The `proofVerifier.Run` path in the arch precompile is reachable by any unprivileged EVM transaction sender: [6](#0-5) 

### Impact Explanation

An attacker who obtains a valid `"FLOW-V0.0-user"` signature from a target Flow account — produced on any network or for any purpose using that tag — can construct a `COAOwnershipProof` and submit it to `verifyCOAOwnershipProof` on a different network or against a different COA. A successful replay causes `isValidSignature` (ERC-1271) to return `ValidERC1271Signature` (`0x1626ba7e`), granting the attacker the ability to pass on-chain EVM authorization checks that rely on COA ownership for access control (e.g., ERC-1271-gated token transfers, multisig approvals, or bridge operations). The attacker gains unauthorized authorization as the COA owner without controlling the underlying Flow account private key at the time of the attack.

### Likelihood Explanation

Medium. The attacker must first obtain a legitimate `"FLOW-V0.0-user"` signature from the target account over a specific data value. This is realistic in cross-network scenarios (e.g., a user who signed a COA ownership proof on Testnet for testing purposes, or signed any data with the same tag for a dApp). The `signedData` is a `bytes32` hash chosen by the EVM caller, so the attacker can select a hash for which they already hold a valid signature. No privileged access or key compromise is required.

### Recommendation

**Short term:** Enforce that `signedData` encodes both the target `evmAddress` and the Flow network identifier (chain ID or `flow.ChainID` string) inside `validateCOAOwnershipProof` before verifying signatures, rather than relying on callers to do so. Reject proofs where `signedData` does not contain the expected binding.

**Long term:** Replace the generic `"FLOW-V0.0-user"` domain separation tag with a COA-ownership-specific tag that encodes the network identity (e.g., `"FLOW-COA-OWNERSHIP-<chainID>-V0"`), analogous to how Flow transaction signing uses the network-scoped `"FLOW-V0.0-transaction"` tag. This ensures COA ownership signatures cannot be replayed across networks or repurposed from other signing contexts.

### Proof of Concept

1. Bob holds a Flow account on both Mainnet and Testnet with the same key pair.
2. On Testnet, Bob signs `hash H` with tag `"FLOW-V0.0-user"` for a legitimate purpose (e.g., a dApp authentication flow). Eve observes this signature.
3. Eve constructs a `COAOwnershipProof` containing Bob's Testnet signature over `H`, pointing to Bob's Mainnet Flow address and COA capability path.
4. Eve calls an EVM contract on Mainnet Flow EVM that invokes `isValidSignature(H, encodedProof)` on Bob's COA.
5. The COA calls `verifyCOAOwnershipProof(coaAddress, H, encodedProof)` on the Cadence Arch precompile.
6. `validateCOAOwnershipProof` verifies Bob's signature over `H` with tag `"FLOW-V0.0-user"` — which is valid because the tag is network-agnostic — and confirms the COA address matches.
7. `isValidSignature` returns `0x1626ba7e` (valid), granting Eve authorization as Bob's COA on Mainnet without Bob's consent. [1](#0-0) [4](#0-3)

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

**File:** model/flow/constants.go (L79-85)
```go
const TransactionTagString = "FLOW-V0.0-transaction"

// TransactionDomainTag is the prefix of all signed transaction payloads.
//
// The tag is the string `TransactionTagString` encoded as UTF-8 bytes,
// right padded to a total length of 32 bytes.
var TransactionDomainTag = paddedDomainTag(TransactionTagString)
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
