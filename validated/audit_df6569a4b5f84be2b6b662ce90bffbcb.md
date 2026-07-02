### Title
COA Ownership Proof Cross-Address Replay Enables ERC-1271 Authentication Bypass for Multi-COA Accounts — (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

`EVM.validateCOAOwnershipProof` does not bind `signedData` to the specific `evmAddress` being proven. A signature produced by a Cadence account to prove ownership of one COA (Cadence-Owned Account) can be replayed verbatim to prove ownership of a different COA on the same Cadence account. This breaks the protocol's custody assumption that a COA ownership proof is exclusive to one EVM address, enabling ERC-1271 authentication bypass for any EVM contract that relies on `verifyCOAOwnershipProof`.

---

### Finding Description

`EVM.validateCOAOwnershipProof` is the on-chain Cadence function that backs the `verifyCOAOwnershipProof` precompile used by COA contracts for ERC-1271 (`isValidSignature`). Its logic is:

1. Verify that the provided `signatures` over `signedData` satisfy the key-weight threshold for the Cadence `address`.
2. Borrow the `CadenceOwnedAccount` resource at the caller-supplied `path` from that account's public capabilities.
3. Compare the resource's EVM address bytes against the caller-supplied `evmAddress`. [1](#0-0) 

The critical gap is step 1: the signature is verified over `signedData` **only**. The `evmAddress` is never included in the signed payload. The code itself documents this: [2](#0-1) 

Because `signedData` does not commit to `evmAddress`, a proof `(address=V, path=/public/coaA, signedData=H, sigs=S, evmAddress=0xAAAA)` that is valid for COA-A can be trivially transformed into `(address=V, path=/public/coaB, signedData=H, sigs=S, evmAddress=0xBBBB)` that is valid for COA-B — using the **same signatures** — as long as both COAs belong to the same Cadence account `V`.

The borrow at line 1095 uses an **unauthorized** reference type `&EVM.CadenceOwnedAccount`: [3](#0-2) 

This is consistent with the FVM's `ValidateAccountCapabilitiesGet` enforcement, which only blocks entitlement-bearing borrows from public paths: [4](#0-3) 

The `address()` accessor on `CadenceOwnedAccount` is `access(all)`, so the unauthorized borrow is sufficient to read the EVM address and pass the address-match check at line 1097–1105. [5](#0-4) 

The ERC-1271 entry point in the COA Solidity contract calls the precompile with `address(this)` as the EVM address: [6](#0-5) 

The precompile routes to `validateCOAOwnershipProof` via `coaOwnershipProofValidator`, passing the proof's `CapabilityPath` and `Address` fields directly from the attacker-supplied encoded proof: [7](#0-6) 

The `COAOwnershipProof` struct that is RLP-encoded and submitted as `_sig` contains the attacker-controllable `CapabilityPath`: [8](#0-7) 

---

### Impact Explanation

An attacker who observes a valid COA ownership proof `(signedData=H, sigs=S)` submitted on-chain for COA-A can construct a new proof for COA-B (same Cadence account, different public path, different EVM address) using the identical signatures. Submitting this forged proof to any EVM contract that calls `isValidSignature` on COA-B will return `ValidERC1271Signature`. Any EVM contract that gates asset transfers, approvals, or governance votes behind ERC-1271 ownership verification of a COA is vulnerable: the attacker can impersonate the COA-B owner and trigger those protected actions, leading to cross-VM asset loss or unauthorized EVM-side authorization.

---

### Likelihood Explanation

**Medium-low.** Two conditions must hold simultaneously:

1. The victim Cadence account holds **more than one COA** (uncommon today but not prohibited; the protocol places no limit).
2. The attacker has observed a valid proof `(signedData=H, sigs=S)` for COA-A on-chain (all transaction arguments are public).

Both conditions are realistic as multi-COA usage grows. The attacker needs no privileged access, no staked node, and no key material — only a previously broadcast proof.

---

### Recommendation

Bind `signedData` to the specific `evmAddress` inside `validateCOAOwnershipProof` before verifying signatures, or require callers to include `evmAddress` in the signed payload and enforce this at the protocol level rather than leaving it as a caller convention. Concretely, the function should hash `signedData || evmAddress` and verify signatures over that composite value, making cross-address replay cryptographically impossible.

---

### Proof of Concept

```
Setup:
  Cadence account V owns:
    COA-A stored at /storage/coaA, published at /public/coaA, EVM address 0xAAAA
    COA-B stored at /storage/coaB, published at /public/coaB, EVM address 0xBBBB

Step 1 — Victim produces a legitimate proof for COA-A:
  proof_A = {
    Address:        V,
    CapabilityPath: "coaA",
    KeyIndices:     [0],
    Signatures:     [sig_V_over_H],   // V signs hash H
  }
  Victim submits proof_A to EVM contract X calling isValidSignature(H, encode(proof_A))
  on COA-A (0xAAAA). This succeeds and is recorded on-chain.

Step 2 — Attacker observes proof_A from chain history.

Step 3 — Attacker constructs forged proof for COA-B:
  proof_B = {
    Address:        V,
    CapabilityPath: "coaB",   // changed
    KeyIndices:     [0],
    Signatures:     [sig_V_over_H],   // SAME signature, SAME hash H
  }

Step 4 — Attacker calls isValidSignature(H, encode(proof_B)) on COA-B (0xBBBB)
  in EVM contract Y.

Step 5 — validateCOAOwnershipProof executes:
  - Verifies sig_V_over_H against V's key 0 over H → PASS (same sig, same hash)
  - Borrows acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaB) → COA-B
  - Checks COA-B.address().bytes == 0xBBBB → PASS
  - Returns isValid: true

Result: EVM contract Y believes the attacker has proven ownership of COA-B (0xBBBB)
and releases protected assets or grants authorization.
```

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L546-550)
```text
        access(all)
        view fun address(): EVMAddress {
            // Always create a new EVMAddress instance
            return EVMAddress(bytes: self.addressBytes)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1001-1018)
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

**File:** fvm/environment/facade_env.go (L390-404)
```go
func (env *facadeEnvironment) ValidateAccountCapabilitiesGet(
	_ interpreter.AccountCapabilityGetValidationContext,
	_ interpreter.AddressValue,
	_ interpreter.PathValue,
	wantedBorrowType *sema.ReferenceType,
	_ *sema.ReferenceType,
) (bool, error) {
	_, hasEntitlements := wantedBorrowType.Authorization.(sema.EntitlementSetAccess)
	if hasEntitlements {
		// TODO: maybe abort
		//return false, &interpreter.GetCapabilityError{}
		return false, nil
	}
	return true, nil
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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
