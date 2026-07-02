### Title
Cross-COA Signature Replay via Missing `evmAddress` Binding in `validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof()` does not enforce that `signedData` encodes the `evmAddress` being claimed. A signature produced by a Cadence account for one COA (Cadence-Owned Account) can be replayed against a different COA owned by the same Cadence account, causing the second COA's ERC-1271 `isValidSignature` to return `ValidERC1271Signature` for a hash the owner never authorized for that COA.

### Finding Description

`EVM.validateCOAOwnershipProof()` in `fvm/evm/stdlib/contract.cdc` performs two checks:

1. Verifies that the provided `signatures` are cryptographically valid over `signedData` using the Cadence account's keys.
2. Verifies that the COA resource at the given `path` in the given Cadence `address` has an EVM address matching the supplied `evmAddress`.

The function explicitly documents the gap:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [1](#0-0) 

The `CapabilityPath` is attacker-controlled — it is embedded inside the RLP-encoded `COAOwnershipProof` bytes that the caller passes as `_sig` to the COA's `isValidSignature`: [2](#0-1) 

The `COAOwnershipProof` struct contains `KeyIndices`, `Address`, `CapabilityPath`, and `Signatures` — but **not** the target `evmAddress`: [3](#0-2) 

The `evmAddress` argument to `validateCOAOwnershipProof` comes from `address(this)` in the Solidity call — i.e., the COA being queried — not from the signed data: [4](#0-3) 

The signature verification step only checks that the signatures are valid over `signedData` for the Cadence account's keys: [5](#0-4) 

The COA address check only verifies that the COA at the attacker-supplied `path` matches `evmAddress`: [6](#0-5) 

Because neither check binds the signature to the specific COA being claimed, an attacker can:

1. Observe a valid `COAOwnershipProof` that Alice produced for **COA-A** (e.g., from a legitimate ERC-1271 interaction), which contains `{Address: 0xAlice, CapabilityPath: "coaA", Signatures: [sig_over_hash]}`.
2. Construct a modified proof `{Address: 0xAlice, CapabilityPath: "coaB", Signatures: [sig_over_hash]}` pointing to **COA-B**.
3. Call `COA_B.isValidSignature(_hash, maliciousProof)`.
4. The precompile calls `validateCOAOwnershipProof(0xAlice, "coaB", _hash, ..., 0xCOA_B)`.
5. Signature check passes (same keys, same `_hash`). COA address check passes (COA at `"coaB"` is `0xCOA_B`). Returns `isValid: true`.

The full call chain is: EVM transaction → `COA.isValidSignature` → `cadenceArch.staticcall(verifyCOAOwnershipProof)` → `proofVerifier.Run` → `coaOwnershipProofValidator` → `backend.Invoke("EVM.validateCOAOwnershipProof")`. [7](#0-6) [8](#0-7) 

### Impact Explanation

An unprivileged EVM transaction sender can make any COA appear to have authorized a `bytes32` hash it never signed for, as long as the Cadence account that owns that COA also owns at least one other COA for which a valid signature over that hash exists. This constitutes unauthorized ERC-1271 identity impersonation of a COA, enabling the attacker to pass ERC-1271-based authentication checks (NFT approvals, token transfers, protocol access gates) on behalf of a COA they do not control. This is a cross-VM asset authorization bypass.

**Impact: 3**

### Likelihood Explanation

The attack requires: (a) the victim Cadence account to own at least two COAs, and (b) the attacker to obtain a valid `COAOwnershipProof` the victim produced for one of those COAs. Condition (a) is non-standard today (most wallets create one COA per account) but is fully supported by the protocol and increasingly common in smart-contract-controlled accounts. Condition (b) is satisfied whenever the victim has previously called `isValidSignature` on COA-A in a context observable on-chain (e.g., an NFT marketplace ERC-1271 check). The vulnerability is documented in the source code itself, confirming the team is aware of the gap.

**Likelihood: 2**

### Recommendation

Enforce that `signedData` encodes `evmAddress`. The `validateCOAOwnershipProof` function should verify that the 20-byte `evmAddress` is present within `signedData` before accepting the proof as valid. Alternatively, the protocol should construct `signedData` as a commitment that includes the target COA's EVM address (e.g., `keccak256(abi.encode(evmAddress, userHash))`), and document this as a required invariant for all callers. The comment at line 1008 already identifies the correct fix direction. [9](#0-8) 

### Proof of Concept

**Setup:**
- Alice's Cadence account `0xAlice` has two COAs:
  - COA-A at `/public/coaA` → EVM address `0xCOA_A`
  - COA-B at `/public/coaB` → EVM address `0xCOA_B`

**Step 1 — Obtain a legitimate proof for COA-A:**
Alice calls some ERC-1271 verifier with COA-A, producing a valid `COAOwnershipProof`:
```
proof_A = RLP({KeyIndices: [0], Address: 0xAlice, CapabilityPath: "coaA", Signatures: [sig_over_hash]})
```
This proof is observable on-chain.

**Step 2 — Construct a replay proof for COA-B:**
The attacker replaces only `CapabilityPath`:
```
proof_B = RLP({KeyIndices: [0], Address: 0xAlice, CapabilityPath: "coaB", Signatures: [sig_over_hash]})
```

**Step 3 — Call COA-B's `isValidSignature`:**
```solidity
COA_B.isValidSignature(_hash, proof_B)
// internally calls:
// cadenceArch.verifyCOAOwnershipProof(address(COA_B), _hash, proof_B)
// → validateCOAOwnershipProof(0xAlice, "coaB", _hash, [0], [sig_over_hash], 0xCOA_B)
```

**Step 4 — Both checks pass:**
- `sig_over_hash` is valid over `_hash` for Alice's key at index 0 → ✓
- COA at `/public/coaB` has address `0xCOA_B` → ✓
- Returns `ValidationResult(isValid: true)` → `isValidSignature` returns `0x1626ba7e`

**Result:** COA-B is treated as having authorized `_hash`, enabling the attacker to pass any ERC-1271 gate protecting COA-B's assets or permissions, without Alice ever intending to authorize that hash for COA-B. [10](#0-9) [11](#0-10)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1115)
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

        return ValidationResult(
            isValid: false,
            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. Could not borrow the COA resource for account \(address)."
        )
```

**File:** fvm/evm/handler/coa/coa.sol (L113-125)
```text
    // ERC1271 requirement 
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
