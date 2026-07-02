### Title
Cross-Address Replay in `validateCOAOwnershipProof` Allows Forged ERC-1271 Signatures for Any COA of the Same Cadence Account - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.validateCOAOwnershipProof` does not bind the signed data to the specific EVM address (COA) being proven. A signature produced for one COA can be replayed against any other COA owned by the same Cadence account by simply swapping the `CapabilityPath` field in the proof bytes, because `CapabilityPath` is not covered by the signature. This allows an unprivileged attacker who observes a valid on-chain proof for COA_A to forge a passing ERC-1271 ownership proof for COA_B of the same account.

### Finding Description

`EVM.validateCOAOwnershipProof` performs two independent checks:

1. Verifies that the provided `signatures` are valid over `signedData` using the Cadence account's keys.
2. Borrows the `CadenceOwnedAccount` capability at the caller-supplied `path`, then checks that the COA's EVM address matches the supplied `evmAddress`. [1](#0-0) 

The `CapabilityPath` (which determines *which* COA is checked) is part of the RLP-encoded proof bytes but is **never included in `signedData`**. The `COAOwnershipProof` struct encodes `KeyIndices`, `Address`, `CapabilityPath`, and `Signatures`, but the signatures are over an external `signedData` blob that is independent of `CapabilityPath`. [2](#0-1) 

The code itself acknowledges this gap: [3](#0-2) 

The EVM-side COA contract (`coa.sol`) implements ERC-1271 by calling the Cadence Arch precompile with `address(this)` as the `evmAddress` and the caller-supplied `_sig` as the proof bytes: [4](#0-3) 

Because `_sig` is fully attacker-controlled and `CapabilityPath` inside it is not signed, an attacker can swap the path to target a different COA.

### Impact Explanation

If a Cadence account owns two COAs — COA_A (at `/public/coaA`) and COA_B (at `/public/coaB`) — and a valid proof for COA_A is ever published on-chain (e.g., via a transaction calling `EVM.run` that exercises `isValidSignature`), an attacker can:

1. Extract the proof bytes from the on-chain transaction.
2. Re-encode the proof with `CapabilityPath = /public/coaB` while keeping the same `signedData`, `signatures`, and `keyIndices`.
3. Call `COA_B.isValidSignature(same_hash, modified_proof)`.
4. `validateCOAOwnershipProof` returns `isValid: true` for COA_B.

Any EVM protocol relying on ERC-1271 to gate asset transfers, order approvals, or authentication for COA_B will accept the forged signature. This constitutes unauthorized access to on-chain assets controlled by COA_B.

### Likelihood Explanation

**Medium-Low.** The precondition is that the victim Cadence account holds more than one COA — currently uncommon but not prohibited by the protocol. Proof bytes are observable on-chain from any prior `isValidSignature` call. No private key material is needed; the attacker only needs to modify a single RLP field. The attack is fully permissionless and requires no special node role.

### Recommendation

Bind the target EVM address into `signedData` at the protocol level. The `validateCOAOwnershipProof` function should enforce that `signedData` encodes `evmAddress` (e.g., by hashing `evmAddress || signedData` before verification), rather than leaving this as an optional caller responsibility. Alternatively, include `CapabilityPath` and `evmAddress` in the signed payload so that a proof is cryptographically tied to exactly one COA. [5](#0-4) 

### Proof of Concept

```
Setup:
  Alice (Cadence account 0xALICE) creates two COAs:
    COA_A stored at /storage/coaA, published at /public/coaA  → EVM address 0xAAAA
    COA_B stored at /storage/coaB, published at /public/coaB  → EVM address 0xBBBB

Step 1 – Alice legitimately signs hash H for COA_A:
  proof_A = RLP{
    Address:        0xALICE,
    CapabilityPath: "coaA",
    KeyIndices:     [0],
    Signatures:     [Sign(H, Alice_key_0)]
  }
  Alice submits EVM tx: COA_A.isValidSignature(H, proof_A)  → ValidERC1271Signature ✓

Step 2 – Attacker observes proof_A on-chain, re-encodes with different path:
  proof_B = RLP{
    Address:        0xALICE,
    CapabilityPath: "coaB",   ← only change; no re-signing needed
    KeyIndices:     [0],
    Signatures:     [Sign(H, Alice_key_0)]
  }

Step 3 – Attacker calls COA_B.isValidSignature(H, proof_B):
  verifyCOAOwnershipProof(0xBBBB, H, proof_B) is invoked.
  • Signature check: Sign(H, Alice_key_0) over H → PASS (same signedData)
  • Capability borrow at /public/coaB → succeeds
  • COA_B.address() == 0xBBBB == evmAddress → PASS
  → Returns ValidERC1271Signature for COA_B ✓ (forged)
``` [6](#0-5) [7](#0-6)

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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
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

**File:** fvm/evm/handler/precompiles.go (L115-152)
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
```
